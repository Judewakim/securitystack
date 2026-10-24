"""Tests for the alert sender (lambdas/alerter/index.py)."""

from conftest import load_lambda

alerter = load_lambda("alerter")


class Rec:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def publish(self, **kw):
        self.calls.append(("publish", kw))

    def batch_update_findings(self, **kw):
        if self.fail:
            raise RuntimeError("throttled")
        self.calls.append(("update", kw))


FINDING = {
    "Id": "arn:aws:securityhub:us-east-1:111122223333:finding/1",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
    "Title": "S3 general purpose buckets should block public access",
    "Severity": {"Label": "CRITICAL"},
    "AwsAccountId": "111122223333",
    "Region": "us-east-1",
    "Resources": [{"Id": "arn:aws:s3:::acme"}],
    "Description": "Public buckets expose data.",
    "Remediation": {"Recommendation": {"Text": "Turn on Block Public Access.", "Url": "https://docs.aws.amazon.com/x"}},
}


def test_emails_once_then_marks_notified(monkeypatch):
    sns, sh = Rec(), Rec()
    monkeypatch.setattr(alerter, "_sns", sns)
    monkeypatch.setattr(alerter, "_sh", sh)
    monkeypatch.setenv("TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:alerts")
    out = alerter.handler({"detail": {"findings": [FINDING]}}, None)
    assert out == {"sent": 1}
    kind, kw = sns.calls[0]
    assert kw["Subject"].startswith("[CRITICAL]") and len(kw["Subject"]) <= 100
    assert "arn:aws:s3:::acme" in kw["Message"] and "Turn on Block Public Access." in kw["Message"]
    kind, kw = sh.calls[0]
    assert kw["Workflow"] == {"Status": "NOTIFIED"}
    assert kw["FindingIdentifiers"] == [{"Id": FINDING["Id"], "ProductArn": FINDING["ProductArn"]}]


def test_status_update_failure_does_not_lose_the_email(monkeypatch):
    sns = Rec()
    monkeypatch.setattr(alerter, "_sns", sns)
    monkeypatch.setattr(alerter, "_sh", Rec(fail=True))
    monkeypatch.setenv("TOPIC_ARN", "t")
    assert alerter.handler({"detail": {"findings": [FINDING]}}, None) == {"sent": 1}
    assert len(sns.calls) == 1


def test_non_https_fix_links_are_dropped():
    evil = {**FINDING, "Remediation": {"Recommendation": {"Url": "javascript:alert(1)"}}}
    assert "javascript:" not in alerter.render(evil)
