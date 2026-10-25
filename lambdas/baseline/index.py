"""SecurityStack baseline custom resource: turn on what's missing, leave the rest alone.

CloudFormation can't adopt a service that's already on (a second GuardDuty
detector or Security Hub subscription fails the whole stack). So, per region,
this function checks each service and only enables what's missing:

    GuardDuty, Security Hub (+ AWS Foundational and CIS v3.0 standards),
    AWS Config recorder, IAM Access Analyzer, Inspector,
    and in the home region: a multi-region CloudTrail trail and Security Hub
    cross-region finding aggregation.

What it turned on is recorded in SSM Parameter Store, so:
* Delete only removes what SecurityStack added; pre-existing services are untouched.
* If a Create fails halfway, everything this call turned on is undone before
  reporting FAILED (CloudFormation never sends Delete for a failed Create).
* The physical resource ID never changes, so an Update can't trigger a
  replacement that would tear things down.

Opt-in hardening (EBS default encryption, account-wide S3 Block Public Access) is
left on when the stack is deleted, because silently weakening an account is worse.

Deployed inline, so only the standard library and boto3.
"""

import json
import logging
import urllib.request

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

INSPECTOR_TYPES = ["EC2", "ECR", "LAMBDA"]
TRAIL_NAME = "securitystack-trail"
NAME = "securitystack"


def std_arns(partition, region):
    base = f"arn:{partition}:securityhub:{region}::standards"
    return {
        "fsbp": f"{base}/aws-foundational-security-best-practices/v/1.0.0",
        "cis": f"{base}/cis-aws-foundations-benchmark/v/3.0.0",
    }


def _on(props, key, default="true"):
    return str(props.get(key, default)).lower() == "true"


def _code(e):
    return e.response.get("Error", {}).get("Code", "") if isinstance(e, ClientError) else ""


# ---------------------------------------------------------------- CloudFormation I/O


def send_response(event, context, status, data=None, reason=None):
    body = json.dumps({
        "Status": status,
        "Reason": (reason or "See CloudWatch Logs: " + getattr(context, "log_stream_name", "n/a"))[:1000],
        "PhysicalResourceId": physical_id(event),
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": False,
        "Data": data or {},
    }).encode("utf-8")
    req = urllib.request.Request(event["ResponseURL"], data=body, method="PUT",
                                 headers={"Content-Type": "", "Content-Length": str(len(body))})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - CloudFormation presigned URL
        LOG.info("CloudFormation response: %s (%s)", status, resp.status)


def physical_id(event):
    props = event.get("ResourceProperties", {})
    return event.get("PhysicalResourceId") or f"securitystack-baseline-{props.get('Region', 'region')}"


# ------------------------------------------------------------------- ownership ledger


class Ledger:
    """Which components this stack turned on, persisted in SSM."""

    def __init__(self, session, region, stack_name):
        self.ssm = session.client("ssm", region_name=region)
        self.name = f"/securitystack/{stack_name}/{region}/owned"
        self.owned = self._load()

    def _load(self):
        try:
            return set(json.loads(self.ssm.get_parameter(Name=self.name)["Parameter"]["Value"]))
        except ClientError as e:
            if _code(e) == "ParameterNotFound":
                return set()
            raise

    def save(self):
        if self.owned:
            self.ssm.put_parameter(Name=self.name, Value=json.dumps(sorted(self.owned)), Type="String", Overwrite=True)
        else:
            try:
                self.ssm.delete_parameter(Name=self.name)
            except ClientError as e:
                if _code(e) != "ParameterNotFound":
                    raise


# ------------------------------------------------------------------------- components


class Baseline:
    def __init__(self, session, props):
        self.s = session
        self.p = props
        self.region = props["Region"]
        self.partition = props.get("Partition", "aws")
        self.home = _on(props, "IsHomeRegion", "false")
        self.done = []      # components turned on by THIS invocation (for rollback)
        self.notes = {}     # per-component status for the stack's Data output

    def c(self, name):
        return self.s.client(name, region_name=self.region)

    # -- GuardDuty
    def guardduty_on(self):
        gd = self.c("guardduty")
        ids = gd.list_detectors()["DetectorIds"]
        if ids:
            if gd.get_detector(DetectorId=ids[0]).get("Status") != "ENABLED":
                gd.update_detector(DetectorId=ids[0], Enable=True)  # re-enable theirs; stays theirs
                return "re-enabled existing"
            return "already on"
        gd.create_detector(Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES")
        return "created"

    def guardduty_off(self):
        gd = self.c("guardduty")
        for d in gd.list_detectors()["DetectorIds"]:
            gd.delete_detector(DetectorId=d)

    # -- Security Hub
    def _hub_exists(self):
        try:
            self.c("securityhub").describe_hub()
            return True
        except ClientError as e:
            if _code(e) in ("InvalidAccessException", "ResourceNotFoundException"):
                return False
            raise

    def securityhub_on(self):
        if self._hub_exists():
            return "already on"
        self.c("securityhub").enable_security_hub(EnableDefaultStandards=False, ControlFindingGenerator="SECURITY_CONTROL")
        return "created"

    def securityhub_off(self):
        self.c("securityhub").disable_security_hub()

    def _enabled_standards(self):
        sh = self.c("securityhub")
        subs = {}
        for page in sh.get_paginator("get_enabled_standards").paginate():
            for s in page["StandardsSubscriptions"]:
                subs[s["StandardsArn"]] = s["StandardsSubscriptionArn"]
        return subs

    def standard_on(self, key):
        arn = std_arns(self.partition, self.region)[key]
        if arn in self._enabled_standards():
            return "already on"
        self.c("securityhub").batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": arn}])
        return "created"

    def standard_off(self, key):
        arn = std_arns(self.partition, self.region)[key]
        sub = self._enabled_standards().get(arn)
        if sub:
            self.c("securityhub").batch_disable_standards(StandardsSubscriptionArns=[sub])

    def aggregator_on(self):
        sh = self.c("securityhub")
        if sh.list_finding_aggregators().get("FindingAggregators"):
            return "already on"
        sh.create_finding_aggregator(RegionLinkingMode="ALL_REGIONS")
        return "created"

    def aggregator_off(self):
        sh = self.c("securityhub")
        for a in sh.list_finding_aggregators().get("FindingAggregators", []):
            sh.delete_finding_aggregator(FindingAggregatorArn=a["FindingAggregatorArn"])

    # -- AWS Config
    def config_on(self):
        cfg = self.c("config")
        if cfg.describe_configuration_recorders()["ConfigurationRecorders"]:
            return "already on"  # one recorder per region; theirs stays as configured
        cfg.put_configuration_recorder(ConfigurationRecorder={
            "name": NAME,
            "roleARN": self.p["ConfigRoleArn"],
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": self.home},
        })
        if not cfg.describe_delivery_channels()["DeliveryChannels"]:
            cfg.put_delivery_channel(DeliveryChannel={
                "name": NAME,
                "s3BucketName": self.p["LogBucketName"],
                "s3KeyPrefix": "config",
                "configSnapshotDeliveryProperties": {"deliveryFrequency": "TwentyFour_Hours"},
            })
        cfg.start_configuration_recorder(ConfigurationRecorderName=NAME)
        return "created"

    def config_off(self):
        cfg = self.c("config")
        for fn, kw in (
            (cfg.stop_configuration_recorder, {"ConfigurationRecorderName": NAME}),
            (cfg.delete_delivery_channel, {"DeliveryChannelName": NAME}),
            (cfg.delete_configuration_recorder, {"ConfigurationRecorderName": NAME}),
        ):
            try:
                fn(**kw)
            except ClientError as e:
                if not _code(e).startswith("NoSuch"):
                    raise

    # -- IAM Access Analyzer
    def analyzer_on(self):
        aa = self.c("accessanalyzer")
        if aa.list_analyzers(type="ACCOUNT")["analyzers"]:
            return "already on"
        aa.create_analyzer(analyzerName=NAME, type="ACCOUNT")
        return "created"

    def analyzer_off(self):
        try:
            self.c("accessanalyzer").delete_analyzer(analyzerName=NAME)
        except ClientError as e:
            if _code(e) != "ResourceNotFoundException":
                raise

    # -- Inspector
    def inspector_on(self):
        insp = self.c("inspector2")
        accounts = insp.batch_get_account_status(accountIds=[self.p["AccountId"]]).get("accounts", [])
        if accounts and accounts[0].get("state", {}).get("status") in ("ENABLED", "ENABLING"):
            return "already on"
        insp.enable(resourceTypes=INSPECTOR_TYPES)
        return "created"

    def inspector_off(self):
        self.c("inspector2").disable(resourceTypes=INSPECTOR_TYPES)

    # -- CloudTrail (home region only)
    def trail_on(self):
        ct = self.c("cloudtrail")
        for t in ct.describe_trails(includeShadowTrails=True)["trailList"]:
            if t.get("IsMultiRegionTrail"):
                home = t["TrailARN"].split(":")[3]
                if self.s.client("cloudtrail", region_name=home).get_trail_status(Name=t["TrailARN"]).get("IsLogging"):
                    return "already on"
        ct.create_trail(
            Name=TRAIL_NAME, S3BucketName=self.p["LogBucketName"], S3KeyPrefix="cloudtrail",
            IsMultiRegionTrail=True, IncludeGlobalServiceEvents=True, EnableLogFileValidation=True,
        )
        ct.start_logging(Name=TRAIL_NAME)
        return "created"

    def trail_off(self):
        try:
            self.c("cloudtrail").delete_trail(Name=TRAIL_NAME)
        except ClientError as e:
            if _code(e) != "TrailNotFoundException":
                raise

    # -- opt-in hardening (never undone)
    def ebs_default_encryption(self):
        ec2 = self.c("ec2")
        if ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
            return "already on"
        ec2.enable_ebs_encryption_by_default()
        return "enabled"

    def s3_account_bpa(self):
        self.s.client("s3control", region_name=self.region).put_public_access_block(
            AccountId=self.p["AccountId"],
            PublicAccessBlockConfiguration={k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
        )
        return "enabled"

    # ------------------------------------------------------------------ orchestration

    def components(self):
        """(key, wanted, on, off), in enable order. Disable runs in reverse."""
        p = self.p
        sh = _on(p, "EnableSecurityHub")
        items = [
            ("guardduty", _on(p, "EnableGuardDuty"), self.guardduty_on, self.guardduty_off),
            ("securityhub", sh, self.securityhub_on, self.securityhub_off),
            ("fsbp", sh, lambda: self.standard_on("fsbp"), lambda: self.standard_off("fsbp")),
            ("cis", sh, lambda: self.standard_on("cis"), lambda: self.standard_off("cis")),
            ("config", _on(p, "EnableConfigRecorder"), self.config_on, self.config_off),
            ("analyzer", _on(p, "EnableAccessAnalyzer"), self.analyzer_on, self.analyzer_off),
            ("inspector", _on(p, "EnableInspector"), self.inspector_on, self.inspector_off),
        ]
        if self.home:
            items += [
                ("aggregator", sh, self.aggregator_on, self.aggregator_off),
                ("trail", _on(p, "CreateTrail"), self.trail_on, self.trail_off),
            ]
        return items

    def apply(self, ledger):
        for key, wanted, on, off in self.components():
            if wanted:
                result = on()
                self.notes[key] = result
                if result == "created":
                    ledger.owned.add(key)
                    self.done.append((key, off))
                    ledger.save()  # persist immediately so a later crash can't orphan it
            elif key in ledger.owned:
                off()
                ledger.owned.discard(key)
                ledger.save()
                self.notes[key] = "turned off"
            else:
                self.notes[key] = "not managed"
        if _on(self.p, "AutoFixEbsDefaultEncryption", "false"):
            self.notes["ebsDefaultEncryption"] = self.ebs_default_encryption()
        if self.home and _on(self.p, "AutoFixS3AccountBlockPublicAccess", "false"):
            self.notes["s3AccountBlockPublicAccess"] = self.s3_account_bpa()

    def rollback(self, ledger):
        for key, off in reversed(self.done):
            try:
                off()
                ledger.owned.discard(key)
            except Exception:
                LOG.exception("Rollback of %s failed", key)
        ledger.save()

    def remove(self, ledger):
        for key, _, _, off in reversed(self.components()):
            if key in ledger.owned:
                try:
                    off()
                    ledger.owned.discard(key)
                except Exception:  # never wedge a stack in DELETE_FAILED
                    LOG.exception("Could not turn off %s during delete", key)
        ledger.save()


def handler(event, context, session=None):
    LOG.info("Event: %s", json.dumps({k: v for k, v in event.items() if k != "ResponseURL"}))
    session = session or boto3.session.Session()
    props = event.get("ResourceProperties", {})
    stack_name = event["StackId"].split("/")[1]
    baseline = Baseline(session, props)
    try:
        ledger = Ledger(session, props["Region"], stack_name)
    except Exception as exc:
        LOG.exception("Ledger unavailable")
        if event["RequestType"] == "Delete":
            return send_response(event, context, "SUCCESS")
        return send_response(event, context, "FAILED", reason=f"{type(exc).__name__}: {exc}")

    if event["RequestType"] == "Delete":
        baseline.remove(ledger)
        return send_response(event, context, "SUCCESS")

    try:
        baseline.apply(ledger)
        send_response(event, context, "SUCCESS", data={k: str(v) for k, v in baseline.notes.items()})
    except Exception as exc:
        LOG.exception("Baseline failed")
        if event["RequestType"] == "Create":
            baseline.rollback(ledger)
        what = next((k for k, *_ in baseline.components() if k not in baseline.notes), "unknown")
        send_response(event, context, "FAILED", reason=f"{what}: {type(exc).__name__}: {exc}")
