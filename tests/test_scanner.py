"""Scanner tests against a moto-simulated AWS account."""

import json
import sys
import urllib.parse

import boto3
import pytest
from moto import mock_aws

from conftest import ROOT

sys.path.insert(0, str(ROOT / "service"))
from scanner import checks  # noqa: E402
from scanner.model import CheckResult  # noqa: E402
from scanner.runner import baseline_launch_url, run_scan, score  # noqa: E402

ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def fresh_results():
    return {cid: CheckResult(c) for cid, c in checks.C.items()}


@pytest.fixture
def insecure_account():
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_user(UserName="alice")
        iam.create_login_profile(UserName="alice", Password="Passw0rd!Passw0rd!")
        arn = iam.create_policy(PolicyName="god-mode", PolicyDocument=json.dumps(ADMIN_DOC))["Policy"]["Arn"]
        iam.attach_user_policy(UserName="alice", PolicyArn=arn)

        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
        sg = ec2.create_security_group(GroupName="wide-open", Description="x", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
        boto3.client("rds", region_name="us-east-1").create_db_instance(
            DBInstanceIdentifier="prod-db", DBInstanceClass="db.t3.micro", Engine="postgres",
            MasterUsername="admin", MasterUserPassword="secretsecret", AllocatedStorage=20,
            PubliclyAccessible=True, StorageEncrypted=False,
        )
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="public-stuff")
        s3.put_public_access_block(
            Bucket="public-stuff",
            PublicAccessBlockConfiguration={k: False for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
        )
        s3.put_bucket_acl(Bucket="public-stuff", ACL="public-read")
        s3.create_bucket(Bucket="private-stuff")
        yield


def test_identity_checks(insecure_account):
    r = fresh_results()
    checks.check_identity(boto3.Session(), r)
    assert r["root-mfa"].status == "FAIL"
    assert r["console-users-mfa"].status == "FAIL"
    assert "alice" in r["console-users-mfa"].findings[0].detail
    assert r["password-policy"].status == "FAIL"
    assert r["admin-policies"].status == "FAIL"
    assert "god-mode" in r["admin-policies"].findings[0].resource


def test_password_policy_passes_when_strong(insecure_account):
    boto3.client("iam").update_account_password_policy(MinimumPasswordLength=16, PasswordReusePrevention=24)
    r = fresh_results()
    checks.check_identity(boto3.Session(), r)
    assert r["password-policy"].status == "PASS"


def test_public_bucket_detected_private_bucket_not(insecure_account):
    r = fresh_results()
    checks.check_s3(boto3.Session(), r, "123456789012")
    assert r["s3-account-bpa"].status == "FAIL"
    flagged = [f.resource for f in r["s3-public-buckets"].findings]
    assert "arn:aws:s3:::public-stuff" in flagged
    assert "arn:aws:s3:::private-stuff" not in flagged


def test_account_bpa_short_circuits_bucket_checks(insecure_account):
    boto3.client("s3control", region_name="us-east-1").put_public_access_block(
        AccountId="123456789012",
        PublicAccessBlockConfiguration={k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
    )
    r = fresh_results()
    checks.check_s3(boto3.Session(), r, "123456789012")
    assert r["s3-account-bpa"].status == "PASS"
    assert r["s3-public-buckets"].status == "PASS"


def test_regional_checks(insecure_account):
    r = fresh_results()
    services = checks.check_region(boto3.Session(), "us-east-1", r)
    assert r["guardduty"].status == "FAIL" and services["guardDuty"] is False
    assert r["open-admin-ports"].status == "FAIL"
    assert "SSH (22)" in r["open-admin-ports"].findings[0].detail
    assert r["rds-public"].status == "FAIL"
    assert r["rds-unencrypted"].status == "FAIL"
    assert r["ebs-default-encryption"].status == "FAIL"


def test_existing_guardduty_is_recognized(insecure_account):
    boto3.client("guardduty", region_name="us-east-1").create_detector(Enable=True)
    r = fresh_results()
    services = checks.check_region(boto3.Session(), "us-east-1", r)
    assert services["guardDuty"] is True
    assert r["guardduty"].status == "PASS"


def test_full_scan_shape(insecure_account):
    result = run_scan(
        boto3.Session(), home_region="us-east-1", regions=["us-east-1"],
        baseline_template_url="https://bucket.s3.us-east-1.amazonaws.com/templates/securitystack-home.template.json",
    )
    assert result["accountId"] == "123456789012"
    assert 0 <= result["score"] <= 100 and result["grade"] in "ABCDF"
    assert result["counts"]["CRITICAL"] >= 2  # root MFA + public bucket
    assert result["fixableBySecurityStack"] >= 3
    statuses = [c["status"] for c in result["checks"]]
    assert statuses == sorted(statuses, key={"FAIL": 0, "UNKNOWN": 1, "PASS": 2}.get)
    url = result["baselineLaunchUrl"]
    assert url.startswith("https://us-east-1.console.aws.amazon.com/cloudformation/")
    assert "stackName=SecurityStack" in url and "param_" not in url  # no switches needed
    json.dumps(result)  # must be serializable for S3


def test_unknown_checks_do_not_count_toward_score():
    r = fresh_results()
    for res in r.values():
        res.unknown("AccessDenied")
    r["root-mfa"].status = "PASS"
    assert score(r) == (100, "A")


@pytest.mark.parametrize(
    "rule,expected",
    [
        ({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, ["all ports"]),
        ({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}, None),
        ({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, []),
        ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}, []),
    ],
)
def test_exposed_ports(rule, expected):
    out = checks._exposed_ports({"IpPermissions": [rule]})
    if expected is None:
        assert "SSH (22)" in out and "RDP (3389)" in out
    else:
        assert out == expected


# ---- review fixes: no false passes -------------------------------------------------


def test_admin_detection_flags_conditions_and_notaction():
    cond = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}
    assert "with conditions" in checks._grants_full_admin(cond)
    assert "except iam:*" in checks._grants_full_admin({"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]})
    assert checks._grants_full_admin({"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}) is None
    assert checks._grants_full_admin({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}) is None


@pytest.mark.parametrize("cidr,open_", [("0.0.0.0/0", True), ("0.0.0.0/1", True), ("10.0.0.0/8", False), ("8.0.0.0/7", True),
                                        ("10.0.0.0/9", False), ("::/0", True), ("2001:db8::/32", False)])
def test_wide_cidrs_count_as_open(cidr, open_):
    assert checks._is_open(cidr) is open_


def test_bucket_access_denied_is_unknown_not_private(insecure_account, monkeypatch):
    from botocore.exceptions import ClientError

    real = checks._bucket_public_reason

    def deny(s3, name):
        if name == "private-stuff":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetBucketAcl")
        return real(s3, name)

    monkeypatch.setattr(checks, "_bucket_public_reason", deny)
    r = fresh_results()
    checks.check_s3(boto3.Session(), r, "123456789012")
    assert r["s3-public-buckets"].status == "FAIL"  # the real public bucket still fails
    assert "private-stuff: AccessDenied" in r["s3-public-buckets"].note
    r2 = fresh_results()
    monkeypatch.setattr(checks, "_bucket_public_reason", lambda s3, name: (_ for _ in ()).throw(
        ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetBucketAcl")))
    checks.check_s3(boto3.Session(), r2, "123456789012")
    assert r2["s3-public-buckets"].status == "UNKNOWN"


def test_region_crash_marks_regional_checks_unknown_not_pass(insecure_account, monkeypatch):
    import scanner.runner as runner

    def boom(session, region, results):
        raise ConnectionError("endpoint unreachable")

    monkeypatch.setattr(runner.checks, "check_region", boom)
    result = run_scan(boto3.Session(), home_region="us-east-1", regions=["us-east-1"])
    by_id = {c["id"]: c for c in result["checks"]}
    for cid in runner.REGIONAL_CHECKS:
        assert by_id[cid]["status"] == "UNKNOWN", cid


def test_global_check_crash_is_unknown(insecure_account, monkeypatch):
    monkeypatch.setattr(checks, "check_identity", lambda *a: (_ for _ in ()).throw(TimeoutError()))
    result = run_scan(boto3.Session(), home_region="us-east-1", regions=["us-east-1"])
    by_id = {c["id"]: c for c in result["checks"]}
    assert by_id["root-mfa"]["status"] == "UNKNOWN" and by_id["admin-policies"]["status"] == "UNKNOWN"


def test_cloudtrail_without_management_events_fails():
    assert checks._logs_management_events({"EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]})
    assert not checks._logs_management_events({"EventSelectors": [{"IncludeManagementEvents": False}]})
    assert not checks._logs_management_events({"EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "ReadOnly"}]})
    assert checks._logs_management_events({"AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]})


def test_legacy_eu_bucket_location_maps_to_region():
    assert checks.LEGACY_S3_LOCATIONS["EU"] == "eu-west-1"
