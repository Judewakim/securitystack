"""Tests for the weekly digest (lambdas/digest/index.py)."""

import json

import boto3
from moto import mock_aws

from conftest import FakeContext, load_lambda

digest = load_lambda("digest")


def finding(title, sev, status=None, region="us-east-1", resource="arn:aws:s3:::bucket-a", url=None):
    f = {"Title": title, "Severity": {"Label": sev}, "Region": region, "Resources": [{"Id": resource}]}
    if status:
        f["Compliance"] = {"Status": status}
    if url:
        f["Remediation"] = {"Recommendation": {"Url": url}}
    return f


SAMPLE = [
    finding("S3 bucket allows public read", "CRITICAL", "FAILED", url="https://docs.aws.amazon.com/fix"),
    finding("S3 bucket allows public read", "CRITICAL", "FAILED", resource="arn:aws:s3:::bucket-b"),
    finding("Root user has no MFA", "CRITICAL", "FAILED"),
    finding("EC2 instance communicating with known bad IP", "HIGH", region="us-west-2"),  # GuardDuty: no Compliance
    finding("Security group allows 0.0.0.0/0 on 22", "HIGH", "FAILED"),
    finding("Logging enabled", "INFORMATIONAL", "PASSED"),
    finding("Encryption enabled", "MEDIUM", "PASSED"),
    finding("Old TLS policy", "LOW", "FAILED"),
]


def test_summarize_scores_and_ranks():
    s = digest.summarize(SAMPLE)
    assert s["checks_passed"] == 2 and s["checks_failed"] == 5
    assert s["score"] == round(100 * 2 / 7)
    assert s["open_by_severity"] == {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 0, "LOW": 1}
    assert s["open_total"] == 6
    assert s["regions_with_findings"] == ["us-east-1", "us-west-2"]
    top = s["top_issues"]
    assert top[0]["title"] == "S3 bucket allows public read" and top[0]["count"] == 2
    assert top[0]["fix_url"] == "https://docs.aws.amazon.com/fix"
    assert [t["severity"] for t in top] == sorted([t["severity"] for t in top], key=digest.SEVERITY_ORDER.index)


def test_summarize_empty_account():
    s = digest.summarize([])
    assert s["score"] is None and s["open_total"] == 0 and s["top_issues"] == []


def test_html_escapes_finding_text():
    evil = [finding("<script>alert(1)</script>", "HIGH", "FAILED", resource='"><img src=x>', url="javascript:alert(1)")]
    out = digest.render_html(digest.summarize(evil), "123456789012", "2026-01-01 00:00", False)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
    assert "javascript:" not in out  # non-https fix links are dropped


class Paged:
    """Minimal Security Hub stub that pages like the real API (100 per page)."""

    def __init__(self, findings):
        self.findings = findings

    def get_paginator(self, name):
        assert name == "get_findings"
        outer = self

        class P:
            def paginate(self, Filters, PaginationConfig):
                assert Filters["RecordState"][0]["Value"] == "ACTIVE"
                for i in range(0, len(outer.findings), 100):
                    yield {"Findings": outer.findings[i : i + 100]}

        return P()


def test_fetch_pages_past_100():
    many = [finding(f"f{i}", "HIGH", "FAILED") for i in range(250)]
    found, truncated = digest.fetch_findings(Paged(many))
    assert len(found) == 250 and not truncated


def test_fetch_caps_huge_accounts():
    many = [finding(f"f{i}", "HIGH", "FAILED") for i in range(350)]
    found, truncated = digest.fetch_findings(Paged(many), max_findings=200)
    assert len(found) == 200 and truncated


@mock_aws
def test_handler_writes_report_and_emails(monkeypatch):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="reports")
    sns = boto3.client("sns", region_name="us-east-1")
    topic = sns.create_topic(Name="alerts")["TopicArn"]
    monkeypatch.setenv("REPORTS_BUCKET", "reports")
    monkeypatch.setenv("TOPIC_ARN", topic)

    real_client = boto3.client
    monkeypatch.setattr(
        digest.boto3, "client",
        lambda name, *a, **kw: Paged(SAMPLE) if name == "securityhub" else real_client(name, *a, **kw),
    )

    result = digest.handler({}, FakeContext())
    assert result["open_total"] == 6
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="reports")["Contents"]]
    assert any(k.endswith("report.html") for k in keys)
    summary_key = next(k for k in keys if k.endswith("summary.json"))
    body = json.loads(s3.get_object(Bucket="reports", Key=summary_key)["Body"].read())
    assert body["score"] == result["score"]
