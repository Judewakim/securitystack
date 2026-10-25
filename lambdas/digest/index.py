"""SecurityStack weekly digest.

Runs on a schedule in the home region. Security Hub's finding aggregator pulls
findings from every linked region into the home region, so one query covers the
whole account. The function:

1. Pages through active Security Hub findings (all of them, not just the first
   100 like v1 did).
2. Builds a plain-English summary: a posture score, counts by severity and the
   most common open problems.
3. Writes an HTML report and a JSON copy to the reports bucket.
4. Emails a short summary (with a console link to the report) through SNS.

Deployed inline, so it uses only the standard library and boto3.
"""

import datetime as dt
import html
import json
import logging
import os
from collections import Counter, defaultdict

import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
MAX_FINDINGS = 20000  # safety cap for very large accounts; noted in the report when hit
TOP_N = 10


def fetch_findings(client, max_findings=MAX_FINDINGS):
    """Return (findings, truncated). Active, unresolved findings only."""
    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [
            {"Value": "NEW", "Comparison": "EQUALS"},
            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
        ],
    }
    findings = []
    paginator = client.get_paginator("get_findings")
    for page in paginator.paginate(Filters=filters, PaginationConfig={"PageSize": 100}):
        findings.extend(page.get("Findings", []))
        if len(findings) >= max_findings:
            return findings[:max_findings], True
    return findings, False


def summarize(findings):
    """Turn raw findings into the numbers the report and email need."""
    compliance = Counter()
    open_by_severity = Counter()
    open_by_title = defaultdict(lambda: {"count": 0, "severity": "INFORMATIONAL", "example": ""})
    regions = set()

    for f in findings:
        status = (f.get("Compliance") or {}).get("Status")
        if status:
            compliance[status] += 1
        if status in ("PASSED", "NOT_AVAILABLE"):
            continue  # passing checks are not problems

        sev = (f.get("Severity") or {}).get("Label", "INFORMATIONAL")
        if sev == "INFORMATIONAL":
            continue
        open_by_severity[sev] += 1
        regions.add(f.get("Region", "unknown"))

        entry = open_by_title[f.get("Title", "Untitled finding")]
        entry["count"] += 1
        if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(entry["severity"]):
            entry["severity"] = sev
        if not entry["example"]:
            resources = f.get("Resources") or [{}]
            entry["example"] = resources[0].get("Id", "")
        remediation = ((f.get("Remediation") or {}).get("Recommendation") or {})
        if remediation.get("Url") and "fix_url" not in entry:
            entry["fix_url"] = remediation["Url"]

    passed = compliance.get("PASSED", 0)
    failed = compliance.get("FAILED", 0)
    score = round(100 * passed / (passed + failed)) if (passed + failed) else None

    top = sorted(
        ({"title": t, **v} for t, v in open_by_title.items()),
        key=lambda x: (SEVERITY_ORDER.index(x["severity"]), -x["count"]),
    )[:TOP_N]

    return {
        "score": score,
        "checks_passed": passed,
        "checks_failed": failed,
        "open_by_severity": {s: open_by_severity.get(s, 0) for s in SEVERITY_ORDER[:4]},
        "open_total": sum(open_by_severity.values()),
        "regions_with_findings": sorted(regions),
        "top_issues": top,
    }


def render_html(summary, account_id, generated_at, truncated):
    e = html.escape
    sev_rows = "".join(
        f"<tr><td>{e(s.title())}</td><td>{summary['open_by_severity'][s]}</td></tr>"
        for s in SEVERITY_ORDER[:4]
    )
    issue_rows = "".join(
        "<tr><td>{sev}</td><td>{title}</td><td>{count}</td><td><code>{ex}</code></td><td>{fix}</td></tr>".format(
            sev=e(i["severity"].title()),
            title=e(i["title"]),
            count=i["count"],
            ex=e(i["example"]),
            fix=(f'<a href="{e(i["fix_url"])}">How to fix</a>' if i.get("fix_url", "").startswith("https://") else ""),
        )
        for i in summary["top_issues"]
    ) or '<tr><td colspan="5">No open issues. Nice work.</td></tr>'
    score = "n/a" if summary["score"] is None else f"{summary['score']}%"
    note = (
        "<p><strong>Note:</strong> this account has more findings than the report limit; counts are a lower bound.</p>"
        if truncated
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SecurityStack weekly report</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
h1{{font-size:1.5rem}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}
td,th{{border:1px solid #ddd;padding:.5rem;text-align:left;font-size:.9rem;vertical-align:top}}
th{{background:#f4f4f4}} .score{{font-size:2.5rem;font-weight:700}} code{{word-break:break-all}}
</style></head><body>
<h1>SecurityStack weekly report</h1>
<p>Account <strong>{e(account_id)}</strong> &middot; generated {e(generated_at)} UTC</p>
<p class="score">{e(score)}</p>
<p>Posture score: share of Security Hub checks passing ({summary['checks_passed']} passed, {summary['checks_failed']} failed).</p>
{note}
<h2>Open issues by severity</h2>
<table><tr><th>Severity</th><th>Open</th></tr>{sev_rows}</table>
<h2>Top issues to fix first</h2>
<table><tr><th>Severity</th><th>Issue</th><th>Count</th><th>Example resource</th><th></th></tr>{issue_rows}</table>
<p>Findings come from AWS Security Hub (AWS Foundational Security Best Practices and CIS AWS Foundations v3.0),
GuardDuty, Inspector and IAM Access Analyzer. This report supports, but does not by itself establish, compliance with any framework.</p>
</body></html>"""


def render_email(summary, account_id, report_link, truncated):
    score = "n/a" if summary["score"] is None else f"{summary['score']}%"
    sev = summary["open_by_severity"]
    lines = [
        f"SecurityStack weekly report for AWS account {account_id}",
        "",
        f"Posture score: {score}",
        f"Open issues: {summary['open_total']} (critical {sev['CRITICAL']}, high {sev['HIGH']}, medium {sev['MEDIUM']}, low {sev['LOW']})",
        "",
        "Fix these first:",
    ]
    if summary["top_issues"]:
        for i in summary["top_issues"][:5]:
            lines.append(f"  - [{i['severity']}] {i['title']} ({i['count']})")
    else:
        lines.append("  - Nothing open. Nice work.")
    if truncated:
        lines += ["", "Note: very large number of findings; counts are a lower bound."]
    lines += ["", f"Full report (sign in to AWS to view): {report_link}"]
    return "\n".join(lines)


FIRST_REPORT_AFTER = 24 * 3600


def first_report_due(ssm, prefix, now_ts):
    """The 'first report' runs on a 6-hourly schedule but sends exactly once, a day after install."""
    try:
        installed = int(ssm.get_parameter(Name=f"{prefix}/installedAt")["Parameter"]["Value"])
    except Exception:
        return False
    if now_ts - installed < FIRST_REPORT_AFTER:
        return False
    try:
        ssm.get_parameter(Name=f"{prefix}/firstReportSent")
        return False
    except ssm.exceptions.ParameterNotFound:
        return True


def handler(event, context):
    region = os.environ.get("AWS_REGION", "us-east-1")
    first = (event or {}).get("mode") == "first"
    prefix = os.environ.get("STATE_PREFIX", "")
    ssm = boto3.client("ssm", region_name=region) if prefix else None
    if first:
        if not ssm or not first_report_due(ssm, prefix, int(dt.datetime.now(dt.timezone.utc).timestamp())):
            return {"skipped": "first report not due"}
    bucket = os.environ["REPORTS_BUCKET"]
    topic_arn = os.environ.get("TOPIC_ARN", "")
    account_id = context.invoked_function_arn.split(":")[4] if context else "unknown"

    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.strftime("%Y-%m-%d")

    findings, truncated = fetch_findings(boto3.client("securityhub", region_name=region))
    summary = summarize(findings)

    s3 = boto3.client("s3", region_name=region)
    html_key = f"reports/weekly/{stamp}/report.html"
    s3.put_object(
        Bucket=bucket,
        Key=html_key,
        Body=render_html(summary, account_id, now.strftime("%Y-%m-%d %H:%M"), truncated).encode("utf-8"),
        ContentType="text/html; charset=utf-8",
    )
    s3.put_object(
        Bucket=bucket,
        Key=f"reports/weekly/{stamp}/summary.json",
        Body=json.dumps({"generated_at": now.isoformat(), "truncated": truncated, **summary}, indent=2).encode("utf-8"),
        ContentType="application/json",
    )
    report_link = f"https://s3.console.aws.amazon.com/s3/object/{bucket}?region={region}&prefix={html_key}"

    if topic_arn:
        score = summary["score"] if summary["score"] is not None else "n/a"
        body = render_email(summary, account_id, report_link, truncated)
        if first:
            body = ("SecurityStack has finished its first full pass over your account. Everything below was "
                    "already there before SecurityStack was installed; from now on you'll get an email only "
                    "when something new and serious appears, plus this report every Monday.\n\n") + body
        boto3.client("sns", region_name=region).publish(
            TopicArn=topic_arn,
            Subject=(f"Your first SecurityStack report: score {score}" if first else f"SecurityStack weekly report: score {score}"),
            Message=body,
        )
    if first:
        ssm.put_parameter(Name=f"{prefix}/firstReportSent", Value=now.isoformat(), Type="String", Overwrite=True)

    LOG.info("Report written to s3://%s/%s", bucket, html_key)
    return {"report": f"s3://{bucket}/{html_key}", "score": summary["score"], "open_total": summary["open_total"]}
