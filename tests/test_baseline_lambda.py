"""The baseline function: turn on what's missing, leave existing services alone,
and on delete remove only what it turned on."""

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from conftest import FakeContext, load_lambda

baseline = load_lambda("baseline")

STACK_ID = "arn:aws:cloudformation:us-east-1:123456789012:stack/SecurityStackHome/abc"
ALL_ON = {
    "EnableGuardDuty": "true", "EnableSecurityHub": "true", "EnableConfigRecorder": "true",
    "EnableAccessAnalyzer": "true", "EnableInspector": "true", "CreateTrail": "true",
}


def event(kind, props=None, home=True):
    return {
        "RequestType": kind,
        "ResponseURL": "https://example.invalid",
        "StackId": STACK_ID,
        "RequestId": "r1",
        "LogicalResourceId": "Baseline",
        "PhysicalResourceId": "securitystack-baseline-us-east-1",
        "ResourceProperties": {
            "Region": "us-east-1", "Partition": "aws", "AccountId": "123456789012",
            "IsHomeRegion": "true" if home else "false",
            "LogBucketName": "ss-logs", "ConfigRoleArn": "arn:aws:iam::123456789012:role/cfg",
            **ALL_ON, **(props or {}),
        },
    }


class FakeInspector:
    def __init__(self, status="DISABLED"):
        self.status, self.calls = status, []

    def batch_get_account_status(self, accountIds):
        return {"accounts": [{"state": {"status": self.status}}]}

    def enable(self, resourceTypes):
        self.calls.append("enable")
        self.status = "ENABLING"

    def disable(self, resourceTypes):
        self.calls.append("disable")
        self.status = "DISABLED"


class FakeSecurityHub:
    """Security Hub with the calls moto doesn't fully cover."""

    def __init__(self, enabled=False):
        self.enabled, self.standards, self.aggregators, self.calls = enabled, {}, [], []

    def describe_hub(self):
        if not self.enabled:
            raise ClientError({"Error": {"Code": "InvalidAccessException", "Message": "not subscribed"}}, "DescribeHub")
        return {}

    def enable_security_hub(self, **kw):
        if self.enabled:
            raise ClientError({"Error": {"Code": "ResourceConflictException", "Message": "already"}}, "EnableSecurityHub")
        self.calls.append("enable")
        self.enabled = True

    def disable_security_hub(self):
        self.calls.append("disable")
        self.enabled, self.standards = False, {}

    def get_paginator(self, name):
        hub = self

        class P:
            def paginate(self):
                yield {"StandardsSubscriptions": [{"StandardsArn": a, "StandardsSubscriptionArn": s} for a, s in hub.standards.items()]}

        return P()

    def batch_enable_standards(self, StandardsSubscriptionRequests):
        for r in StandardsSubscriptionRequests:
            self.standards[r["StandardsArn"]] = "sub/" + r["StandardsArn"].split("/")[-3]

    def batch_disable_standards(self, StandardsSubscriptionArns):
        self.standards = {a: s for a, s in self.standards.items() if s not in StandardsSubscriptionArns}

    def list_finding_aggregators(self):
        return {"FindingAggregators": [{"FindingAggregatorArn": a} for a in self.aggregators]}

    def create_finding_aggregator(self, RegionLinkingMode):
        self.aggregators.append("agg-1")

    def delete_finding_aggregator(self, FindingAggregatorArn):
        self.aggregators.remove(FindingAggregatorArn)


class FakeAnalyzer:
    """moto doesn't implement IAM Access Analyzer."""

    def __init__(self):
        self.names = []

    def list_analyzers(self, type):
        return {"analyzers": [{"name": n, "status": "ACTIVE"} for n in self.names]}

    def create_analyzer(self, analyzerName, type):
        self.names.append(analyzerName)

    def delete_analyzer(self, analyzerName):
        if analyzerName not in self.names:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "x"}}, "DeleteAnalyzer")
        self.names.remove(analyzerName)


@pytest.fixture
def aws(monkeypatch):
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="ss-logs")
        fakes = {"inspector2": FakeInspector(), "securityhub": FakeSecurityHub(), "accessanalyzer": FakeAnalyzer()}
        sent = []
        monkeypatch.setattr(baseline, "send_response",
                            lambda e, c, status, data=None, reason=None: sent.append((status, data or {}, reason)))

        class Session:
            def client(self, name, region_name=None, **kw):
                return fakes.get(name) or boto3.client(name, region_name=region_name or "us-east-1")

        yield Session(), fakes, sent


def run(aws, kind, props=None, home=True):
    session, _, sent = aws
    baseline.handler(event(kind, props, home), FakeContext(), session=session)
    return sent[-1]


def test_fresh_account_turns_everything_on(aws):
    session, fakes, _ = aws
    status, data, reason = run(aws, "Create")
    assert status == "SUCCESS", reason
    for key in ("guardduty", "securityhub", "fsbp", "cis", "config", "analyzer", "inspector", "aggregator", "trail"):
        assert data[key] == "created", (key, data)
    assert boto3.client("guardduty", region_name="us-east-1").list_detectors()["DetectorIds"]
    assert boto3.client("cloudtrail", region_name="us-east-1").get_trail_status(Name="securitystack-trail")["IsLogging"]
    status = boto3.client("config", region_name="us-east-1").describe_configuration_recorder_status()
    assert status["ConfigurationRecordersStatus"][0]["recording"]
    assert len(fakes["securityhub"].standards) == 2


def test_existing_services_are_left_alone(aws):
    """The exact failure from the first real deploy: GuardDuty and Security Hub already on."""
    session, fakes, _ = aws
    gd = boto3.client("guardduty", region_name="us-east-1")
    existing = gd.create_detector(Enable=True)["DetectorId"]
    fakes["securityhub"].enabled = True
    fakes["inspector2"].status = "ENABLED"

    status, data, reason = run(aws, "Create")
    assert status == "SUCCESS", reason
    assert data["guardduty"] == "already on" and data["securityhub"] == "already on"
    assert data["inspector"] == "already on"
    assert data["fsbp"] == "created"  # standards still added to their hub

    run(aws, "Delete")
    assert gd.list_detectors()["DetectorIds"] == [existing]  # theirs survives
    assert fakes["securityhub"].enabled and "disable" not in fakes["securityhub"].calls
    assert fakes["inspector2"].calls == []
    assert fakes["securityhub"].standards == {}  # only what we added is removed


def test_delete_removes_everything_it_created(aws):
    session, fakes, _ = aws
    run(aws, "Create")
    run(aws, "Delete")
    assert boto3.client("guardduty", region_name="us-east-1").list_detectors()["DetectorIds"] == []
    assert not fakes["securityhub"].enabled and fakes["securityhub"].aggregators == []
    assert boto3.client("config", region_name="us-east-1").describe_configuration_recorders()["ConfigurationRecorders"] == []
    assert fakes["accessanalyzer"].names == []
    assert fakes["inspector2"].calls == ["enable", "disable"]
    trails = boto3.client("cloudtrail", region_name="us-east-1").describe_trails()["trailList"]
    assert not any(t["Name"] == "securitystack-trail" for t in trails)


def test_failed_create_rolls_back_what_it_turned_on(aws, monkeypatch):
    session, fakes, sent = aws

    def boom(**kw):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "nope"}}, "Enable")

    monkeypatch.setattr(fakes["inspector2"], "enable", boom)
    status, data, reason = run(aws, "Create")
    assert status == "FAILED" and "inspector" in reason and "AccessDenied" in reason
    # GuardDuty etc. were created before the failure, then rolled back
    assert boto3.client("guardduty", region_name="us-east-1").list_detectors()["DetectorIds"] == []
    assert not fakes["securityhub"].enabled


def test_update_turning_a_service_off_only_removes_ours(aws):
    session, fakes, _ = aws
    run(aws, "Create")
    status, data, _ = run(aws, "Update", {"EnableGuardDuty": "false"})
    assert status == "SUCCESS" and data["guardduty"] == "turned off"
    assert boto3.client("guardduty", region_name="us-east-1").list_detectors()["DetectorIds"] == []


def test_physical_id_never_changes(aws):
    e = event("Update")
    assert baseline.physical_id(e) == "securitystack-baseline-us-east-1"


def test_region_stack_skips_trail_and_aggregator(aws):
    status, data, _ = run(aws, "Create", home=False)
    assert status == "SUCCESS" and "trail" not in data and "aggregator" not in data
    rec = boto3.client("config", region_name="us-east-1").describe_configuration_recorders()["ConfigurationRecorders"][0]
    assert rec["recordingGroup"]["includeGlobalResourceTypes"] is False


def test_existing_trail_is_not_duplicated(aws):
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(Name="theirs", S3BucketName="ss-logs", IsMultiRegionTrail=True)
    ct.start_logging(Name="theirs")
    status, data, _ = run(aws, "Create")
    assert data["trail"] == "already on"


def test_opt_in_hardening_only_when_asked(aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    run(aws, "Create")
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is False
    run(aws, "Update", {"AutoFixEbsDefaultEncryption": "true", "AutoFixS3AccountBlockPublicAccess": "true"})
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is True
    cfg = boto3.client("s3control", region_name="us-east-1").get_public_access_block(AccountId="123456789012")
    assert all(cfg["PublicAccessBlockConfiguration"].values())
    run(aws, "Delete")
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is True  # hardening is never undone


def test_send_response_payload(monkeypatch):
    captured = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        captured["method"], captured["body"] = req.get_method(), req.data
        return Resp()

    monkeypatch.setattr(baseline.urllib.request, "urlopen", fake_urlopen)
    baseline.send_response(event("Create"), FakeContext(), "SUCCESS", {"a": "b"})
    assert captured["method"] == "PUT"
    assert b'"PhysicalResourceId": "securitystack-baseline-us-east-1"' in captured["body"]


def test_install_time_recorded_on_create_and_cleared_on_delete(aws):
    ssm = boto3.client("ssm", region_name="us-east-1")
    run(aws, "Create")
    assert int(ssm.get_parameter(Name="/securitystack/SecurityStackHome/installedAt")["Parameter"]["Value"]) > 0
    run(aws, "Delete")
    import pytest as _p
    with _p.raises(ClientError):
        ssm.get_parameter(Name="/securitystack/SecurityStackHome/installedAt")
