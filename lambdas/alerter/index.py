"""SecurityStack alert sender.

Triggered by EventBridge for new, active HIGH/CRITICAL Security Hub findings.
Sends one readable email per finding through SNS, then marks the finding's
workflow status NOTIFIED. Security Hub re-imports a still-failing finding every
time it re-checks it; without this step the same issue would email again and
again. If the problem is fixed and later comes back, Security Hub resets the
status to NEW and you get a fresh alert.

Deployed inline, so it uses only the standard library and boto3.
"""

import logging
import os

import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

_sns = boto3.client("sns")
_sh = boto3.client("securityhub")


def render(f):
    resource = ((f.get("Resources") or [{}])[0]).get("Id", "unknown")
    fix = ((f.get("Remediation") or {}).get("Recommendation") or {})
    lines = [
        f"SecurityStack alert ({f.get('Severity', {}).get('Label', '?')})",
        "",
        f.get("Title", "Untitled finding"),
        "",
        f"Account: {f.get('AwsAccountId', '?')}",
        f"Region: {f.get('Region', '?')}",
        f"Resource: {resource}",
        "",
        "What it means: " + (f.get("Description") or "See Security Hub for details."),
    ]
    if fix.get("Text"):
        lines += ["", "How to fix it: " + fix["Text"]]
    if str(fix.get("Url", "")).startswith("https://"):
        lines += [fix["Url"]]
    lines += ["", "Open Security Hub in the AWS console for full details."]
    return "\n".join(lines)


def handler(event, context):
    topic = os.environ["TOPIC_ARN"]
    findings = event.get("detail", {}).get("findings", [])
    sent = []
    for f in findings:
        subject = f"[{f.get('Severity', {}).get('Label', '?')}] {f.get('Title', 'Security finding')}"[:100]
        _sns.publish(TopicArn=topic, Subject=subject, Message=render(f))
        sent.append({"Id": f["Id"], "ProductArn": f["ProductArn"]})
    if sent:
        try:
            _sh.batch_update_findings(
                FindingIdentifiers=sent,
                Workflow={"Status": "NOTIFIED"},
                Note={"Text": "Emailed by SecurityStack", "UpdatedBy": "securitystack"},
            )
        except Exception:  # the email already went out; a failed status update only risks a repeat
            LOG.exception("Could not mark findings NOTIFIED")
    return {"sent": len(sent)}
