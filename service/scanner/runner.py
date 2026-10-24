"""Runs every check and builds the scan result the web app renders."""

import datetime as dt
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config

from . import checks
from .model import SEVERITIES, WEIGHTS, CheckResult

BOTO_CONFIG = Config(retries={"max_attempts": 8, "mode": "adaptive"}, connect_timeout=5, read_timeout=20)


class _ConfiguredSession:
    """Wraps a boto3 Session so every client gets retries/timeouts.

    boto3 Sessions are not thread-safe, so each worker thread gets its own
    Session built from the same frozen credentials (see `fork`).
    """

    def __init__(self, session):
        self._s = session

    def client(self, name, region_name=None):
        return self._s.client(name, region_name=region_name, config=BOTO_CONFIG)

    def fork(self):
        creds = self._s.get_credentials().get_frozen_credentials()
        return _ConfiguredSession(boto3.Session(
            aws_access_key_id=creds.access_key,
            aws_secret_access_key=creds.secret_key,
            aws_session_token=creds.token,
        ))


REGIONAL_CHECKS = (
    "guardduty", "securityhub", "config", "access-analyzer", "inspector",
    "ebs-default-encryption", "open-admin-ports", "rds-public", "rds-unencrypted",
)


def _guard(results, check_ids, fn, *args):
    """Run a group of checks; an unexpected error marks them UNKNOWN, never PASS."""
    try:
        return fn(*args)
    except Exception as exc:
        for cid in check_ids:
            results[cid].unknown(f"check failed: {type(exc).__name__}")
        return None


def enabled_regions(session, home_region):
    ec2 = session.client("ec2", region_name=home_region)
    regions = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
    return sorted(r["RegionName"] for r in regions["Regions"])


def score(results):
    evaluated = [r for r in results.values() if r.status in ("PASS", "FAIL")]
    total = sum(WEIGHTS[r.check.severity] for r in evaluated)
    lost = sum(WEIGHTS[r.check.severity] for r in evaluated if r.status == "FAIL")
    value = round(100 * (total - lost) / total) if total else 0
    grade = "A" if value >= 90 else "B" if value >= 80 else "C" if value >= 70 else "D" if value >= 60 else "F"
    return value, grade


def baseline_launch_url(template_url, home_region, home_services, multi_region_trail):
    """Pre-filled Launch Stack link: services that already exist are switched off,
    because CloudFormation would fail trying to create a second one."""
    if not template_url:
        return None
    def create(key):
        # Only ask CloudFormation to create a service we *know* is absent. If the
        # scan couldn't tell (access denied), leave it off so the stack can't fail.
        return "true" if home_services.get(key) is False else "false"

    params = {
        "stackName": "SecurityStack",
        "templateURL": template_url,
        "param_EnableGuardDuty": create("guardDuty"),
        "param_EnableSecurityHub": create("securityHub"),
        "param_EnableConfigRecorder": create("configRecorder"),
        "param_EnableAccessAnalyzer": create("accessAnalyzer"),
        "param_EnableInspector": create("inspector"),
        # Unknown trail status -> don't create one (a duplicate trail is billed).
        "param_CreateTrail": "true" if multi_region_trail is False else "false",
    }
    return (
        f"https://{home_region}.console.aws.amazon.com/cloudformation/home?region={home_region}"
        f"#/stacks/quickcreate?{urllib.parse.urlencode(params)}"
    )


def run_scan(session, home_region="us-east-1", regions=None, baseline_template_url=None, max_workers=8):
    """Scan the account behind `session`. Read-only."""
    s = _ConfiguredSession(session)
    started = dt.datetime.now(dt.timezone.utc)
    account_id = session.client("sts", region_name=home_region).get_caller_identity()["Account"]
    regions = regions or enabled_regions(s, home_region)
    if home_region not in regions:
        regions = [home_region, *regions]

    results = {cid: CheckResult(c) for cid, c in checks.C.items()}

    _guard(results, ("root-mfa", "root-access-keys", "console-users-mfa", "stale-access-keys", "password-policy", "admin-policies"),
           checks.check_identity, s, results)
    _guard(results, ("s3-account-bpa", "s3-public-buckets"), checks.check_s3, s, results, account_id)
    trail = _guard(results, ("cloudtrail",), checks.check_cloudtrail, s, results, home_region) or {"multiRegionTrail": None}

    def scan_region(region):
        return checks.check_region(s.fork(), region, results)

    services_by_region = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {region: pool.submit(scan_region, region) for region in regions}
        for region, fut in futures.items():
            try:
                services_by_region[region] = fut.result()
            except Exception as exc:  # one broken region must not sink the scan, or pass its checks
                services_by_region[region] = {"error": type(exc).__name__}
                for cid in REGIONAL_CHECKS:
                    results[cid].unknown(f"{region}: {type(exc).__name__}")

    value, grade = score(results)
    ordered = sorted(
        results.values(),
        key=lambda r: ({"FAIL": 0, "UNKNOWN": 1, "PASS": 2}[r.status], SEVERITIES.index(r.check.severity)),
    )
    failing = [r for r in ordered if r.status == "FAIL"]
    counts = {sev: sum(len(r.findings) for r in failing if r.check.severity == sev) for sev in SEVERITIES}

    return {
        "version": 1,
        "accountId": account_id,
        "homeRegion": home_region,
        "regionsScanned": regions,
        "startedAt": started.isoformat(),
        "finishedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "score": value,
        "grade": grade,
        "counts": counts,
        "checksFailed": len(failing),
        "checksPassed": sum(1 for r in ordered if r.status == "PASS"),
        "checksUnknown": sum(1 for r in ordered if r.status == "UNKNOWN"),
        "fixableBySecurityStack": sum(1 for r in failing if r.check.fixed_by_securitystack),
        "checks": [r.to_dict() for r in ordered],
        "servicesByRegion": services_by_region,
        "baselineLaunchUrl": baseline_launch_url(
            baseline_template_url, home_region, services_by_region.get(home_region, {}), trail["multiRegionTrail"]
        ),
    }
