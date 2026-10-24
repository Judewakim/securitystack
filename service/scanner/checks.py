"""Read-only security checks.

Global checks run once per account; regional checks run in every enabled region.
Each check function receives a boto3 Session and a CheckResult to fill in.
Access-denied or throttling errors mark the check UNKNOWN rather than passing it.
"""

import csv
import datetime as dt
import io
import time

from botocore.exceptions import ClientError

from .model import Check

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis"}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
STALE_KEY_DAYS = 90
MAX_BUCKETS = 500

# ---------------------------------------------------------------------------- checks

C = {
    c.id: c
    for c in [
        Check("root-mfa", "Root user has no MFA", "CRITICAL", "Identity",
              "Anyone with the root password controls the entire account, including billing and deleting everything.",
              "Sign in as root and add an MFA device (a hardware key or authenticator app).", ok="Root user has MFA"),
        Check("root-access-keys", "Root user has access keys", "CRITICAL", "Identity",
              "Root keys cannot be limited by any policy. If leaked, an attacker has full control.",
              "Delete the root access keys and use IAM roles or users with least privilege instead.", ok="Root user has no access keys"),
        Check("console-users-mfa", "Console users without MFA", "HIGH", "Identity",
              "A stolen or guessed password is enough to sign in.",
              "Require MFA for every IAM user with console access, or move people to IAM Identity Center.", ok="All console users have MFA"),
        Check("stale-access-keys", "Unused or old access keys", "MEDIUM", "Identity",
              f"Keys unused for {STALE_KEY_DAYS}+ days are forgotten credentials that still work if leaked.",
              "Deactivate and delete keys that aren't used; rotate the rest regularly.", ok="No unused or old access keys"),
        Check("password-policy", "Weak or missing password policy", "MEDIUM", "Identity",
              "Without a policy, IAM users can set short, easily guessed passwords.",
              "Set an IAM password policy: at least 14 characters, and prevent reuse.", ok="Strong password policy"),
        Check("admin-policies", "Custom policies grant full admin (*:*)", "HIGH", "Identity",
              "Policies allowing every action on every resource give whoever holds them total control.",
              "Replace *:* with only the actions and resources each workload needs.", ok="No custom full-admin policies"),
        Check("s3-account-bpa", "S3 Block Public Access is off for the account", "MEDIUM", "Data",
              "Any bucket can be made public by a single policy or ACL mistake.",
              "Turn on account-level S3 Block Public Access (SecurityStack can do this as an opt-in auto-fix).", True, ok="S3 Block Public Access is on for the account"),
        Check("s3-public-buckets", "Publicly accessible S3 buckets", "CRITICAL", "Data",
              "Anyone on the internet can read (and sometimes write) the data in these buckets.",
              "Remove the public policy/ACL and turn on Block Public Access, unless the bucket intentionally hosts public files.", ok="No public S3 buckets"),
        Check("cloudtrail", "No multi-region CloudTrail trail is logging", "HIGH", "Logging",
              "Without an audit trail you can't see who did what, or investigate an incident.",
              "Create a multi-region trail with log file validation (SecurityStack does this).", True, ok="Multi-region CloudTrail is logging"),
        Check("guardduty", "GuardDuty threat detection is off", "HIGH", "Detection",
              "Compromised credentials, crypto-mining and data exfiltration go unnoticed.",
              "Enable GuardDuty in every region you use (SecurityStack does this).", True, ok="GuardDuty is on"),
        Check("securityhub", "Security Hub is off", "MEDIUM", "Detection",
              "There's no continuous check of your configuration against security best practices.",
              "Enable Security Hub with the AWS Foundational and CIS standards (SecurityStack does this).", True, ok="Security Hub is on"),
        Check("config", "AWS Config is not recording", "MEDIUM", "Logging",
              "There's no history of how resources changed, which audits and investigations rely on.",
              "Turn on the AWS Config recorder (SecurityStack does this).", True, ok="AWS Config is recording"),
        Check("access-analyzer", "IAM Access Analyzer is off", "LOW", "Detection",
              "Resources shared with outside accounts or the public aren't flagged.",
              "Create an account analyzer in each region; it's free (SecurityStack does this).", True, ok="IAM Access Analyzer is on"),
        Check("inspector", "Inspector vulnerability scanning is off", "MEDIUM", "Detection",
              "Known software vulnerabilities in EC2, container images and Lambda go unnoticed.",
              "Enable Amazon Inspector (SecurityStack does this).", True, ok="Inspector is scanning"),
        Check("ebs-default-encryption", "EBS encryption by default is off", "MEDIUM", "Data",
              "New disks and snapshots can be created unencrypted.",
              "Turn on EBS encryption by default in each region (SecurityStack can do this as an opt-in auto-fix).", True, ok="EBS encryption by default is on"),
        Check("open-admin-ports", "Security groups open admin/database ports to the internet", "HIGH", "Network",
              "SSH, RDP and database ports open to 0.0.0.0/0 are scanned and brute-forced constantly.",
              "Restrict these rules to known IPs, or use Session Manager / a VPN instead.", ok="No admin or database ports open to the internet"),
        Check("rds-public", "Publicly accessible databases", "HIGH", "Network",
              "The database endpoint is reachable from the internet, protected only by its password.",
              "Set PubliclyAccessible to false and reach the database through private networking.", ok="No publicly accessible databases"),
        Check("rds-unencrypted", "Unencrypted databases", "MEDIUM", "Data",
              "Data at rest and its snapshots are not encrypted.",
              "Restore from an encrypted snapshot copy to encrypt an existing database.", ok="All databases are encrypted"),
    ]
}


def _code(err):
    return err.response.get("Error", {}).get("Code", "Error") if isinstance(err, ClientError) else type(err).__name__


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _parse_time(value):
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


# ---------------------------------------------------------------- global (account) checks


def credential_report(iam, wait_seconds=20):
    deadline = time.monotonic() + wait_seconds
    while True:
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        if time.monotonic() > deadline:
            raise TimeoutError("credential report not ready")
        time.sleep(2)
    content = iam.get_credential_report()["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def check_identity(session, results):
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if not summary.get("AccountMFAEnabled"):
            results["root-mfa"].fail("root user")
        if summary.get("AccountAccessKeysPresent"):
            results["root-access-keys"].fail("root user")
    except ClientError as e:
        results["root-mfa"].unknown(_code(e))
        results["root-access-keys"].unknown(_code(e))

    try:
        rows = credential_report(iam)
        now = _now()
        for row in rows:
            user = row.get("user")
            if user == "<root_account>":
                continue
            if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
                results["console-users-mfa"].fail(row.get("arn", user), detail=f"IAM user {user}")
            for n in ("1", "2"):
                if row.get(f"access_key_{n}_active") != "true":
                    continue
                last_used = _parse_time(row.get(f"access_key_{n}_last_used_date"))
                rotated = _parse_time(row.get(f"access_key_{n}_last_rotated"))
                reference = last_used or rotated
                if reference and (now - reference).days >= STALE_KEY_DAYS:
                    age = (now - reference).days
                    what = "last used" if last_used else "created and never used"
                    results["stale-access-keys"].fail(row.get("arn", user), detail=f"Key {n} for {user}: {what} {age} days ago")
    except (ClientError, TimeoutError) as e:
        results["console-users-mfa"].unknown(_code(e))
        results["stale-access-keys"].unknown(_code(e))

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        if policy.get("MinimumPasswordLength", 0) < 14 or not policy.get("PasswordReusePrevention"):
            results["password-policy"].fail(
                "account password policy",
                detail=f"Minimum length {policy.get('MinimumPasswordLength', 0)}; reuse prevention {'on' if policy.get('PasswordReusePrevention') else 'off'}",
            )
    except ClientError as e:
        if _code(e) == "NoSuchEntity":
            results["password-policy"].fail("account password policy", detail="No password policy is set")
        else:
            results["password-policy"].unknown(_code(e))

    try:
        for page in iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=True):
            for p in page["Policies"]:
                doc = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
                if _grants_full_admin(doc):
                    results["admin-policies"].fail(p["Arn"], detail=f"Policy {p['PolicyName']} is attached to {p.get('AttachmentCount', '?')} identities")
    except ClientError as e:
        results["admin-policies"].unknown(_code(e))


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _grants_full_admin(doc):
    if isinstance(doc, str):  # some SDKs return URL-encoded JSON
        import json
        import urllib.parse

        doc = json.loads(urllib.parse.unquote(doc))
    for stmt in _as_list(doc.get("Statement", [])):
        if stmt.get("Effect") != "Allow" or "NotAction" in stmt or "Condition" in stmt:
            continue
        if "*" in _as_list(stmt.get("Action", [])) and "*" in _as_list(stmt.get("Resource", [])):
            return True
    return False


def check_s3(session, results, account_id):
    s3control = session.client("s3control", region_name="us-east-1")
    account_bpa_on = False
    try:
        cfg = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        account_bpa_on = all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
    except ClientError as e:
        if _code(e) != "NoSuchPublicAccessBlockConfiguration":
            results["s3-account-bpa"].unknown(_code(e))
    if not account_bpa_on and results["s3-account-bpa"].status != "UNKNOWN":
        results["s3-account-bpa"].fail("account", detail="Account-level Block Public Access is not fully enabled")

    if account_bpa_on:
        return  # account-level BPA overrides bucket policies and ACLs: nothing can be public

    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        results["s3-public-buckets"].unknown(_code(e))
        return
    if len(buckets) > MAX_BUCKETS:
        results["s3-public-buckets"].note = f"Checked the first {MAX_BUCKETS} of {len(buckets)} buckets."
    for b in buckets[:MAX_BUCKETS]:
        name = b["Name"]
        try:
            region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            rs3 = session.client("s3", region_name=region)
            public_reason = _bucket_public_reason(rs3, name)
            if public_reason:
                results["s3-public-buckets"].fail(f"arn:aws:s3:::{name}", region=region, detail=public_reason)
        except ClientError as e:
            if _code(e) not in ("NoSuchBucket", "AccessDenied"):
                results["s3-public-buckets"].unknown(f"{name}: {_code(e)}")


def _bucket_public_reason(s3, name):
    bpa = {}
    try:
        bpa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if _code(e) != "NoSuchPublicAccessBlockConfiguration":
            raise
    if not bpa.get("RestrictPublicBuckets"):
        try:
            if s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]:
                return "Bucket policy allows public access"
        except ClientError as e:
            if _code(e) != "NoSuchBucketPolicy":
                raise
    if not bpa.get("IgnorePublicAcls"):
        for grant in s3.get_bucket_acl(Bucket=name).get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri.endswith("/global/AllUsers") or uri.endswith("/global/AuthenticatedUsers"):
                return f"ACL grants {grant.get('Permission')} to {uri.rsplit('/', 1)[-1]}"
    return None


def check_cloudtrail(session, results, home_region):
    ct = session.client("cloudtrail", region_name=home_region)
    try:
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        for t in trails:
            if not t.get("IsMultiRegionTrail"):
                continue
            arn = t["TrailARN"]
            region = arn.split(":")[3]
            status = session.client("cloudtrail", region_name=region).get_trail_status(Name=arn)
            if status.get("IsLogging"):
                return {"multiRegionTrail": True}
        results["cloudtrail"].fail("account", detail="No multi-region trail is currently logging")
    except ClientError as e:
        results["cloudtrail"].unknown(_code(e))
    return {"multiRegionTrail": False}


# ------------------------------------------------------------------------ regional checks


def check_region(session, region, results):
    """Run all regional checks. Returns which baseline services already exist here."""
    services = {}

    gd = session.client("guardduty", region_name=region)
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        enabled = any(gd.get_detector(DetectorId=d).get("Status") == "ENABLED" for d in detectors)
        services["guardDuty"] = bool(detectors)
        if not enabled:
            results["guardduty"].fail(f"GuardDuty ({region})", region=region)
    except ClientError as e:
        results["guardduty"].unknown(f"{region}: {_code(e)}")

    sh = session.client("securityhub", region_name=region)
    try:
        sh.describe_hub()
        services["securityHub"] = True
    except ClientError as e:
        if _code(e) in ("InvalidAccessException", "ResourceNotFoundException"):
            services["securityHub"] = False
            results["securityhub"].fail(f"Security Hub ({region})", region=region)
        else:
            results["securityhub"].unknown(f"{region}: {_code(e)}")

    cfg = session.client("config", region_name=region)
    try:
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        services["configRecorder"] = bool(recorders)
        statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", []) if recorders else []
        if not any(s.get("recording") for s in statuses):
            results["config"].fail(f"AWS Config ({region})", region=region)
    except ClientError as e:
        results["config"].unknown(f"{region}: {_code(e)}")

    aa = session.client("accessanalyzer", region_name=region)
    try:
        analyzers = [a for p in aa.get_paginator("list_analyzers").paginate(type="ACCOUNT") for a in p["analyzers"]]
        services["accessAnalyzer"] = bool(analyzers)
        if not any(a.get("status") == "ACTIVE" for a in analyzers):
            results["access-analyzer"].fail(f"IAM Access Analyzer ({region})", region=region)
    except ClientError as e:
        results["access-analyzer"].unknown(f"{region}: {_code(e)}")

    try:
        insp = session.client("inspector2", region_name=region)
        accounts = insp.batch_get_account_status().get("accounts", [])
        status = accounts[0]["state"]["status"] if accounts else "DISABLED"
        services["inspector"] = status in ("ENABLED", "ENABLING")
        if not services["inspector"]:
            results["inspector"].fail(f"Inspector ({region})", region=region)
    except ClientError as e:
        results["inspector"].unknown(f"{region}: {_code(e)}")

    ec2 = session.client("ec2", region_name=region)
    try:
        if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
            results["ebs-default-encryption"].fail(f"EBS ({region})", region=region)
    except ClientError as e:
        results["ebs-default-encryption"].unknown(f"{region}: {_code(e)}")

    try:
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                exposed = _exposed_ports(sg)
                if exposed:
                    results["open-admin-ports"].fail(
                        f"{sg['GroupId']} ({sg.get('GroupName', '')})", region=region, detail="Open to the internet: " + ", ".join(exposed)
                    )
    except ClientError as e:
        results["open-admin-ports"].unknown(f"{region}: {_code(e)}")

    rds = session.client("rds", region_name=region)
    try:
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                arn = db.get("DBInstanceArn", db["DBInstanceIdentifier"])
                if db.get("PubliclyAccessible"):
                    results["rds-public"].fail(arn, region=region, detail=f"{db.get('Engine', '')} instance {db['DBInstanceIdentifier']}")
                if not db.get("StorageEncrypted"):
                    results["rds-unencrypted"].fail(arn, region=region, detail=f"{db.get('Engine', '')} instance {db['DBInstanceIdentifier']}")
    except ClientError as e:
        results["rds-public"].unknown(f"{region}: {_code(e)}")
        results["rds-unencrypted"].unknown(f"{region}: {_code(e)}")

    return services


def _exposed_ports(sg):
    exposed = []
    for rule in sg.get("IpPermissions", []):
        cidrs = {r.get("CidrIp") for r in rule.get("IpRanges", [])} | {r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])}
        if not cidrs & OPEN_CIDRS:
            continue
        if rule.get("IpProtocol") == "-1":
            exposed.append("all ports")
            continue
        if rule.get("IpProtocol") not in ("tcp", "6"):
            continue
        lo, hi = rule.get("FromPort", 0), rule.get("ToPort", 65535)
        for port, name in ADMIN_PORTS.items():
            if lo <= port <= hi:
                exposed.append(f"{name} ({port})")
    return sorted(set(exposed))
