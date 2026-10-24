"""End-to-end tests of the free-scan API + worker against moto."""

import json
import re
import sys
import time
import urllib.parse

import boto3
import pytest
from moto import mock_aws

from conftest import ROOT

sys.path.insert(0, str(ROOT / "service"))
import api  # noqa: E402
import worker  # noqa: E402


def http(method, path, body=None, scan_id=None, ip="203.0.113.7"):
    return {
        "requestContext": {"http": {"method": method, "sourceIp": "130.176.0.1"}},
        "headers": {"x-forwarded-for": f"198.51.100.99, {ip}"},  # first entry is client-supplied (spoofable)
        "rawPath": path,
        "pathParameters": {"scanId": scan_id} if scan_id else None,
        "body": json.dumps(body) if body is not None else None,
    }


@pytest.fixture
def svc(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="scans",
            KeySchema=[{"AttributeName": "scanId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "scanId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="results")

        invoked = []
        for mod in (api, worker):
            monkeypatch.setattr(mod, "TABLE", "scans")
            monkeypatch.setattr(mod, "RESULTS_BUCKET", "results")
            monkeypatch.setattr(mod, "_ddb", ddb)
            monkeypatch.setattr(mod, "_s3", s3)
        monkeypatch.setattr(api, "SCAN_ROLE_TEMPLATE_URL", "https://t.s3.us-east-1.amazonaws.com/templates/scan-role.yaml")
        monkeypatch.setattr(worker, "_sts", boto3.client("sts", region_name="us-east-1"))

        class FakeLambda:
            def invoke(self, **kw):
                invoked.append(json.loads(kw["Payload"]))

        monkeypatch.setattr(api, "_lambda", FakeLambda())
        yield invoked


def new_scan(ip="203.0.113.7"):
    r = api.handler(http("POST", "/api/scans", {"homeRegion": "us-east-1"}, ip=ip), None)
    assert r["statusCode"] == 201, r
    body = json.loads(r["body"])
    params = urllib.parse.parse_qs(body["roleLaunchUrl"].split("?", 2)[-1])
    suffix = params["param_ScanSuffix"][0]
    return body["scanId"], suffix, params, body


def role_for(suffix, account="123456789012"):
    return f"arn:aws:iam::{account}:role/SecurityStackScanRole-{suffix}"


def start(scan_id, arn, ip="203.0.113.7"):
    return api.handler(http("POST", f"/api/scans/{scan_id}/start", {"roleArn": arn}, scan_id, ip=ip), None)


def test_full_flow(svc):
    scan_id, suffix, params, body = new_scan()
    assert len(scan_id) == 32 and re.fullmatch(r"[a-z0-9]{8}", suffix)
    assert params["param_ExternalId"][0].startswith("ss-")
    assert params["stackName"] == [f"SecurityStackScanRole-{suffix}"]  # unique per scan: no "already exists"
    assert "param_ScannerRoleArn" not in params  # the trusted principal is not a parameter
    assert "externalId" not in body  # not needed by the page, so not returned

    assert start(scan_id, role_for(suffix))["statusCode"] == 202
    assert svc == [{"scanId": scan_id}]
    assert start(scan_id, role_for(suffix))["statusCode"] == 409  # not twice while queued

    worker.handler({"scanId": scan_id}, None)
    got = json.loads(api.handler(http("GET", f"/api/scans/{scan_id}", scan_id=scan_id), None)["body"])
    assert got["status"] == "DONE", got
    assert got["result"]["accountId"] == "123456789012"
    assert got["result"]["grade"] in "ABCDF"


def test_role_from_another_scan_is_refused(svc):
    scan_a, suffix_a, _, _ = new_scan()
    scan_b, suffix_b, _, _ = new_scan()
    assert start(scan_b, role_for(suffix_a))["statusCode"] == 409
    assert svc == []


@pytest.mark.parametrize("arn", [
    "arn:aws:iam::123456789012:role/Admin",
    "arn:aws:iam::123456789012:user/SecurityStackScanRole-abcd1234",
    "arn:aws:iam::1234:role/SecurityStackScanRole-abcd1234",
    "arn:aws:iam::123456789012:role/SecurityStackScanRole-us-east-1",
    "",
])
def test_rejects_malformed_roles(svc, arn):
    scan_id, _, _, _ = new_scan()
    assert start(scan_id, arn)["statusCode"] == 400
    assert svc == []


def test_unknown_or_malformed_ids(svc):
    assert api.handler(http("GET", "/api/scans/x", scan_id="x"), None)["statusCode"] == 404
    fake = "A" * 32
    assert api.handler(http("GET", f"/api/scans/{fake}", scan_id=fake), None)["statusCode"] == 404
    assert start(fake, role_for("abcd1234"))["statusCode"] == 409


def test_bad_input(svc):
    assert api.handler(http("POST", "/api/scans", {"homeRegion": "../../etc"}), None)["statusCode"] == 400
    bad = http("POST", "/api/scans")
    bad["body"] = "not json"
    assert api.handler(bad, None)["statusCode"] == 400


def test_worker_failure_is_friendly_and_retryable(svc, monkeypatch):
    scan_id, suffix, _, _ = new_scan()
    start(scan_id, role_for(suffix))

    from botocore.exceptions import ClientError

    def deny(*a, **k):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "AssumeRole")

    monkeypatch.setattr(worker, "assume", deny)
    worker.handler({"scanId": scan_id}, None)
    got = json.loads(api.handler(http("GET", f"/api/scans/{scan_id}", scan_id=scan_id), None)["body"])
    assert got["status"] == "FAILED" and "RoleArn" in got["error"]
    assert start(scan_id, role_for(suffix))["statusCode"] == 202  # a failed scan can be retried


def test_stuck_scan_can_be_retried_after_timeout(svc):
    scan_id, suffix, _, _ = new_scan()
    assert start(scan_id, role_for(suffix))["statusCode"] == 202
    table = api._ddb.Table("scans")
    table.update_item(Key={"scanId": scan_id}, UpdateExpression="SET #s = :r, updatedAt = :old",
                      ExpressionAttributeNames={"#s": "status"},
                      ExpressionAttributeValues={":r": "RUNNING", ":old": int(time.time()) - api.STALE_SECONDS - 5})
    assert start(scan_id, role_for(suffix))["statusCode"] == 202


def test_retry_limit(svc):
    scan_id, suffix, _, _ = new_scan()
    table = api._ddb.Table("scans")
    for _ in range(api.MAX_ATTEMPTS):
        assert start(scan_id, role_for(suffix))["statusCode"] == 202
        table.update_item(Key={"scanId": scan_id}, UpdateExpression="SET #s = :f",
                          ExpressionAttributeNames={"#s": "status"}, ExpressionAttributeValues={":f": "FAILED"})
    assert start(scan_id, role_for(suffix))["statusCode"] == 409


def test_per_ip_rate_limit_uses_real_viewer_ip(svc, monkeypatch):
    monkeypatch.setitem(api.LIMITS, "create", 3)
    for _ in range(3):
        new_scan(ip="203.0.113.50")
    r = api.handler(http("POST", "/api/scans", {}, ip="203.0.113.50"), None)
    assert r["statusCode"] == 429
    new_scan(ip="203.0.113.51")  # a different viewer is unaffected
    assert api.client_ip(http("GET", "/x", ip="203.0.113.9")) == "203.0.113.9"  # last XFF entry, not the spoofable first


def test_expired_results_return_404_not_500(svc):
    scan_id, suffix, _, _ = new_scan()
    start(scan_id, role_for(suffix))
    worker.handler({"scanId": scan_id}, None)
    api._s3.delete_object(Bucket="results", Key=f"results/{scan_id}.json")  # S3 lifecycle got there first
    assert api.handler(http("GET", f"/api/scans/{scan_id}", scan_id=scan_id), None)["statusCode"] == 404


def test_service_stack_synthesizes_cleanly():
    import aws_cdk as cdk
    from aws_cdk.assertions import Annotations, Match, Template
    from cdk_nag import AwsSolutionsChecks

    from securitystack.service_stack import ScanServiceStack

    app = cdk.App()
    stack = ScanServiceStack(app, "Svc", env=cdk.Environment(region="us-east-1"))
    cdk.Aspects.of(app).add(AwsSolutionsChecks())
    assembly = app.synth()
    # The published scan-role template has the placeholder principal replaced by
    # this deployment's worker role (resolved at deploy time via a marker).
    import pathlib
    published = list(pathlib.Path(assembly.directory).glob("**/scan-role.yaml"))
    assert published, "scan-role.yaml must be part of the templates deployment"
    body = published[0].read_text()
    assert "000000000000" not in body and "SecurityStackScanWorker" in body
    assert Annotations.from_stack(stack).find_error("*", Match.string_like_regexp("AwsSolutions-.*")) == []
    t = Template.from_stack(stack)
    t.has_resource_properties("AWS::IAM::Role", {"RoleName": "SecurityStackScanWorker"})
    t.has_resource_properties("AWS::DynamoDB::GlobalTable", {"TimeToLiveSpecification": {"AttributeName": "ttl", "Enabled": True}})
    policy = json.dumps(t.find_resources("AWS::S3::BucketPolicy"))
    assert "PublicReadTemplatesOnly" in policy and "templates/*" in policy
    csp = json.dumps(t.find_resources("AWS::CloudFront::ResponseHeadersPolicy"))
    assert "frame-ancestors 'none'" in csp and "script-src 'self'" in csp
    tables = json.dumps(t.find_resources("AWS::DynamoDB::GlobalTable"))
    assert '"PointInTimeRecoveryEnabled": true' not in tables
    for fn in t.find_resources("AWS::Lambda::Function").values():
        assert "ReservedConcurrentExecutions" not in fn["Properties"]  # opt-in only


def test_scan_role_policy_covers_exactly_what_the_scanner_calls():
    """Every AWS call the scanner makes must be allowed, and nothing broader."""
    text = (ROOT / "templates" / "scan-role.yaml").read_text()
    allowed = set(re.findall(r"^\s+- ([a-z0-9-]+:[A-Za-z]+)\s*$", text, re.M))
    assert "SecurityAudit" not in text.split("Resources:")[1]
    assert "000000000000:role/SecurityStackScanWorker" in text
    assert "ScannerRoleArn" not in text

    called = set()
    for path in (ROOT / "service" / "scanner").glob("*.py"):
        src = path.read_text()
        called |= set(re.findall(r"\.([a-z_]+)\(", src)) | set(re.findall(r'get_paginator\("([a-z_]+)"\)', src))
    action_for = {
        "describe_regions": "ec2:DescribeRegions", "describe_security_groups": "ec2:DescribeSecurityGroups",
        "get_ebs_encryption_by_default": "ec2:GetEbsEncryptionByDefault",
        "get_account_summary": "iam:GetAccountSummary", "generate_credential_report": "iam:GenerateCredentialReport",
        "get_credential_report": "iam:GetCredentialReport", "get_account_password_policy": "iam:GetAccountPasswordPolicy",
        "list_policies": "iam:ListPolicies", "get_policy_version": "iam:GetPolicyVersion",
        "get_public_access_block": None,  # s3control -> s3:GetAccountPublicAccessBlock, s3 -> s3:GetBucketPublicAccessBlock
        "list_buckets": "s3:ListAllMyBuckets", "get_bucket_location": "s3:GetBucketLocation",
        "get_bucket_policy_status": "s3:GetBucketPolicyStatus", "get_bucket_acl": "s3:GetBucketAcl",
        "describe_trails": "cloudtrail:DescribeTrails", "get_trail_status": "cloudtrail:GetTrailStatus",
        "get_event_selectors": "cloudtrail:GetEventSelectors",
        "list_detectors": "guardduty:ListDetectors", "get_detector": "guardduty:GetDetector",
        "describe_hub": "securityhub:DescribeHub",
        "describe_configuration_recorders": "config:DescribeConfigurationRecorders",
        "describe_configuration_recorder_status": "config:DescribeConfigurationRecorderStatus",
        "list_analyzers": "access-analyzer:ListAnalyzers", "batch_get_account_status": "inspector2:BatchGetAccountStatus",
        "describe_db_instances": "rds:DescribeDBInstances",
    }
    aws_calls = called & set(action_for)
    assert aws_calls == set(action_for), set(action_for) - aws_calls  # mapping stays in sync with the code
    needed = {a for a in action_for.values() if a} | {"s3:GetAccountPublicAccessBlock", "s3:GetBucketPublicAccessBlock"}
    assert allowed == needed, (needed - allowed, allowed - needed)
