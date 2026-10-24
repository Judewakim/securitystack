"""Tests for the settings custom resource (lambdas/settings/index.py)."""

import boto3
import pytest
from moto import mock_aws

from conftest import FakeContext, load_lambda

settings = load_lambda("settings")

STACK_ID = "arn:aws:cloudformation:us-east-1:123456789012:stack/SecurityStackHome/abc"


def event(request_type, props=None, physical_id=None):
    e = {
        "RequestType": request_type,
        "ResponseURL": "https://example.invalid/response",
        "StackId": STACK_ID,
        "RequestId": "req-1",
        "LogicalResourceId": "Settings",
        "ResourceProperties": {"Region": "us-east-1", "AccountId": "123456789012", **(props or {})},
    }
    if physical_id:
        e["PhysicalResourceId"] = physical_id
    return e


@pytest.fixture
def responses(monkeypatch):
    sent = []

    def fake_send(event, context, status, data=None, physical_id=None, reason=None):
        sent.append({"status": status, "data": data or {}, "physical_id": physical_id, "reason": reason})

    monkeypatch.setattr(settings, "send_response", fake_send)
    return sent


class FakeInspector:
    def __init__(self, status="DISABLED", fail=False):
        self.status, self.fail, self.calls = status, fail, []

    def batch_get_account_status(self, accountIds):
        return {"accounts": [{"accountId": accountIds[0], "state": {"status": self.status}}]}

    def enable(self, resourceTypes):
        if self.fail:
            raise RuntimeError("AccessDenied")
        self.calls.append(("enable", tuple(resourceTypes)))
        self.status = "ENABLING"

    def disable(self, resourceTypes):
        self.calls.append(("disable", tuple(resourceTypes)))
        self.status = "DISABLED"


@pytest.fixture
def inspector(monkeypatch):
    fake = FakeInspector()
    real_client = boto3.client

    def client(name, *a, **kw):
        return fake if name == "inspector2" else real_client(name, *a, **kw)

    monkeypatch.setattr(settings.boto3, "client", client)
    return fake


def test_create_enables_inspector_and_marks_ownership(responses, inspector):
    settings.handler(event("Create", {"EnableInspector": "true"}), FakeContext())
    assert responses[-1]["status"] == "SUCCESS"
    assert settings.MARKER_ENABLED_BY_STACK in responses[-1]["physical_id"]
    assert inspector.calls == [("enable", ("EC2", "ECR", "LAMBDA"))]


def test_create_does_not_claim_preexisting_inspector(responses, inspector):
    inspector.status = "ENABLED"
    settings.handler(event("Create", {"EnableInspector": "true"}), FakeContext())
    assert responses[-1]["status"] == "SUCCESS"
    assert settings.MARKER_ENABLED_BY_STACK not in responses[-1]["physical_id"]
    assert inspector.calls == []


def test_delete_only_disables_what_the_stack_enabled(responses, inspector):
    settings.handler(event("Delete", physical_id="securitystack-settings-us-east-1"), FakeContext())
    assert inspector.calls == []
    settings.handler(
        event("Delete", physical_id="securitystack-settings-us-east-1|" + settings.MARKER_ENABLED_BY_STACK),
        FakeContext(),
    )
    assert inspector.calls == [("disable", ("EC2", "ECR", "LAMBDA"))]
    assert all(r["status"] == "SUCCESS" for r in responses)


def test_failure_is_reported_as_failed_not_success(responses, monkeypatch):
    """v1 always said SUCCESS. A failure must surface in CloudFormation."""
    fake = FakeInspector(fail=True)
    monkeypatch.setattr(settings.boto3, "client", lambda name, *a, **kw: fake)
    settings.handler(event("Create", {"EnableInspector": "true"}), FakeContext())
    assert responses[-1]["status"] == "FAILED"
    assert "AccessDenied" in responses[-1]["reason"]


@mock_aws
def test_ebs_default_encryption_opt_in(responses, inspector):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is False

    settings.handler(event("Create", {"EnableInspector": "false", "AutoFixEbsDefaultEncryption": "false"}), FakeContext())
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is False  # off by default: untouched

    settings.handler(event("Update", {"EnableInspector": "false", "AutoFixEbsDefaultEncryption": "true"}), FakeContext())
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is True
    assert responses[-1]["data"]["EbsDefaultEncryption"] == "enabled"


@mock_aws
def test_s3_account_block_public_access_opt_in(responses, inspector):
    settings.handler(
        event("Create", {"EnableInspector": "false", "AutoFixS3AccountBlockPublicAccess": "true"}), FakeContext()
    )
    cfg = boto3.client("s3control", region_name="us-east-1").get_public_access_block(AccountId="123456789012")
    assert all(cfg["PublicAccessBlockConfiguration"].values())


def test_send_response_payload(monkeypatch):
    captured = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        captured["method"] = req.get_method()
        captured["body"] = req.data
        return Resp()

    monkeypatch.setattr(settings.urllib.request, "urlopen", fake_urlopen)
    settings.send_response(event("Create"), FakeContext(), "SUCCESS", {"a": "b"}, "pid")
    assert captured["method"] == "PUT"
    assert b'"PhysicalResourceId": "pid"' in captured["body"]
