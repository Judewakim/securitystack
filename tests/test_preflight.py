"""Preflight: existing services must be switched off so the stack can't fail on them."""

import sys

import boto3
from moto import mock_aws

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import preflight  # noqa: E402


@mock_aws
def test_fresh_account_creates_everything():
    found = preflight.detect(boto3.Session(region_name="us-east-1"), "us-east-1")
    assert found["EnableGuardDuty"] == "true"
    assert found["EnableConfigRecorder"] == "true"
    assert found["CreateTrail"] == "true"


@mock_aws
def test_existing_services_are_switched_off():
    boto3.client("guardduty", region_name="us-east-1").create_detector(Enable=True)
    boto3.client("securityhub", region_name="us-east-1").enable_security_hub()
    found = preflight.detect(boto3.Session(region_name="us-east-1"), "us-east-1")
    assert found["EnableGuardDuty"] == "false"
    assert found["EnableSecurityHub"] == "false"


def test_unknown_means_off(monkeypatch):
    from botocore.exceptions import ClientError

    class Denied:
        def __getattr__(self, name):
            def call(*a, **k):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, name)
            return call

    class S:
        def client(self, *a, **k):
            return Denied()

    found = preflight.detect(S(), "us-east-1")
    assert set(found.values()) == {"false"}  # never risk a failed stack


@mock_aws
def test_cli_output_format(capsys):
    preflight.main(["--region", "us-east-1"])
    out = capsys.readouterr().out.strip()
    assert out.startswith("--parameters SecurityStackHome:EnableGuardDuty=")
