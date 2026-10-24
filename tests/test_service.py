"""End-to-end tests of the free-scan API + worker against moto."""

import json
import sys

import boto3
import pytest
from moto import mock_aws

from conftest import ROOT

sys.path.insert(0, str(ROOT / "service"))
import api  # noqa: E402
import worker  # noqa: E402

ROLE_ARN = "arn:aws:iam::123456789012:role/SecurityStackScanRole-us-east-1"


def http(method, path, body=None, scan_id=None):
    return {
        "requestContext": {"http": {"method": method}},
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
        boto3.client("iam").create_role(RoleName="SecurityStackScanRole-us-east-1", AssumeRolePolicyDocument="{}")

        invoked = []
        for mod in (api, worker):
            monkeypatch.setattr(mod, "TABLE", "scans")
            monkeypatch.setattr(mod, "RESULTS_BUCKET", "results")
            monkeypatch.setattr(mod, "_ddb", ddb)
            monkeypatch.setattr(mod, "_s3", s3)
        monkeypatch.setattr(api, "WORKER_ROLE_ARN", "arn:aws:iam::999999999999:role/SecurityStackScanWorker")
        monkeypatch.setattr(api, "SCAN_ROLE_TEMPLATE_URL", "https://t.s3.us-east-1.amazonaws.com/templates/scan-role.yaml")
        monkeypatch.setattr(worker, "_sts", boto3.client("sts", region_name="us-east-1"))

        class FakeLambda:
            def invoke(self, **kw):
                invoked.append(json.loads(kw["Payload"]))

        monkeypatch.setattr(api, "_lambda", FakeLambda())
        yield invoked


def test_full_flow(svc):
    created = api.handler(http("POST", "/api/scans", {"homeRegion": "us-east-1"}), None)
    assert created["statusCode"] == 201
    body = json.loads(created["body"])
    scan_id, ext = body["scanId"], body["externalId"]
    assert len(scan_id) == 32 and ext.startswith("ss-")
    assert "param_ExternalId=" + ext in body["roleLaunchUrl"]
    assert "quickcreate" in body["roleLaunchUrl"]

    started = api.handler(http("POST", f"/api/scans/{scan_id}/start", {"roleArn": ROLE_ARN}, scan_id), None)
    assert started["statusCode"] == 202
    assert svc == [{"scanId": scan_id}]

    # Starting twice is refused while queued.
    again = api.handler(http("POST", f"/api/scans/{scan_id}/start", {"roleArn": ROLE_ARN}, scan_id), None)
    assert again["statusCode"] == 409

    worker.handler({"scanId": scan_id}, None)
    got = json.loads(api.handler(http("GET", f"/api/scans/{scan_id}", scan_id=scan_id), None)["body"])
    assert got["status"] == "DONE", got
    assert got["result"]["accountId"] == "123456789012"
    assert got["result"]["grade"] in "ABCDF"


@pytest.mark.parametrize("arn", [
    "arn:aws:iam::123456789012:role/Admin",
    "arn:aws:iam::123456789012:user/SecurityStackScanRole",
    "arn:aws:iam::1234:role/SecurityStackScanRole-x",
    "",
])
def test_rejects_other_roles(svc, arn):
    scan_id = json.loads(api.handler(http("POST", "/api/scans", {}), None)["body"])["scanId"]
    r = api.handler(http("POST", f"/api/scans/{scan_id}/start", {"roleArn": arn}, scan_id), None)
    assert r["statusCode"] == 400
    assert svc == []


def test_unknown_or_malformed_ids(svc):
    assert api.handler(http("GET", "/api/scans/x", scan_id="x"), None)["statusCode"] == 404
    fake = "A" * 32
    assert api.handler(http("GET", f"/api/scans/{fake}", scan_id=fake), None)["statusCode"] == 404
    r = api.handler(http("POST", f"/api/scans/{fake}/start", {"roleArn": ROLE_ARN}, fake), None)
    assert r["statusCode"] == 409


def test_bad_input(svc):
    assert api.handler(http("POST", "/api/scans", {"homeRegion": "../../etc"}), None)["statusCode"] == 400
    bad = http("POST", "/api/scans")
    bad["body"] = "not json"
    assert api.handler(bad, None)["statusCode"] == 400


def test_worker_failure_is_friendly_and_retryable(svc, monkeypatch):
    scan_id = json.loads(api.handler(http("POST", "/api/scans", {}), None)["body"])["scanId"]
    api.handler(http("POST", f"/api/scans/{scan_id}/start", {"roleArn": ROLE_ARN}, scan_id), None)

    from botocore.exceptions import ClientError

    def deny(*a, **k):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "AssumeRole")

    monkeypatch.setattr(worker, "assume", deny)
    worker.handler({"scanId": scan_id}, None)
    got = json.loads(api.handler(http("GET", f"/api/scans/{scan_id}", scan_id=scan_id), None)["body"])
    assert got["status"] == "FAILED"
    assert "RoleArn" in got["error"]
    # A failed scan can be retried.
    assert api.handler(http("POST", f"/api/scans/{scan_id}/start", {"roleArn": ROLE_ARN}, scan_id), None)["statusCode"] == 202


def test_retry_limit(svc, monkeypatch):
    scan_id = json.loads(api.handler(http("POST", "/api/scans", {}), None)["body"])["scanId"]
    table = api._ddb.Table("scans")
    for _ in range(api.MAX_ATTEMPTS):
        assert api.handler(http("POST", f"/api/scans/{scan_id}/start", {"roleArn": ROLE_ARN}, scan_id), None)["statusCode"] == 202
        table.update_item(Key={"scanId": scan_id}, UpdateExpression="SET #s = :f",
                          ExpressionAttributeNames={"#s": "status"}, ExpressionAttributeValues={":f": "FAILED"})
    assert api.handler(http("POST", f"/api/scans/{scan_id}/start", {"roleArn": ROLE_ARN}, scan_id), None)["statusCode"] == 409


def test_service_stack_synthesizes_cleanly():
    import aws_cdk as cdk
    from aws_cdk.assertions import Annotations, Match, Template
    from cdk_nag import AwsSolutionsChecks

    from securitystack.service_stack import ScanServiceStack

    app = cdk.App()
    stack = ScanServiceStack(app, "Svc", env=cdk.Environment(region="us-east-1"))
    cdk.Aspects.of(app).add(AwsSolutionsChecks())
    app.synth()
    assert Annotations.from_stack(stack).find_error("*", Match.string_like_regexp("AwsSolutions-.*")) == []
    t = Template.from_stack(stack)
    t.has_resource_properties("AWS::IAM::Role", {"RoleName": "SecurityStackScanWorker"})
    t.has_resource_properties("AWS::DynamoDB::GlobalTable", {"TimeToLiveSpecification": {"AttributeName": "ttl", "Enabled": True}})
    policy = json.dumps(t.find_resources("AWS::S3::BucketPolicy"))
    assert "PublicReadTemplatesOnly" in policy and "templates/*" in policy
    csp = json.dumps(t.find_resources("AWS::CloudFront::ResponseHeadersPolicy"))
    assert "frame-ancestors 'none'" in csp and "script-src 'self'" in csp
