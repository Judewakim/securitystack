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
import time

import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

_sns = boto3.client("sns")
_sh = boto3.client("securityhub")
_ssm = boto3.client("ssm")

QUIET_SECONDS = 24 * 3600  # first day: everything already wrong shows up at once


def in_quiet_period():
    """True during the first 24h after install. Those findings go into one first report instead."""
    name = os.environ.get("INSTALLED_AT_PARAM")
    if not name:
        return False
    try:
        installed = int(_ssm.get_parameter(Name=name)["Parameter"]["Value"])
    except Exception:
        return False  # unknown install time: alert normally rather than risk silence
    return time.time() - installed < QUIET_SECONDS


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
    quiet = in_quiet_period()
    sent = []
    for f in findings:
        if not quiet:
            subject = f"[{f.get('Severity', {}).get('Label', '?')}] {f.get('Title', 'Security finding')}"[:100]
            _sns.publish(TopicArn=topic, Subject=subject, Message=render(f))
        sent.append({"Id": f["Id"], "ProductArn": f["ProductArn"]})
    if sent:
        note = "Found during setup; included in your first SecurityStack report" if quiet else "Emailed by SecurityStack"
        try:
            _sh.batch_update_findings(
                FindingIdentifiers=sent,
                Workflow={"Status": "NOTIFIED"},
                Note={"Text": note, "UpdatedBy": "securitystack"},
            )
        except Exception:  # the email already went out; a failed status update only risks a repeat
            LOG.exception("Could not mark findings NOTIFIED")
    return {"sent": 0 if quiet else len(sent), "held_for_first_report": len(sent) if quiet else 0}
