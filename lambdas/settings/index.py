"""SecurityStack account-settings custom resource.

Handles the few account settings CloudFormation has no native resource for:

* Amazon Inspector (v2) scanning for EC2, ECR and Lambda.
* EBS encryption-by-default for the region (opt-in auto-fix).
* Account-level S3 Block Public Access (opt-in auto-fix, home region only).

Design rules (these fix bugs in v1):

* Report FAILED to CloudFormation when something fails. v1 reported SUCCESS no
  matter what, so customers saw a green stack while services were off.
* Never undo something the stack did not do. Inspector is only disabled on stack
  delete if this stack is the one that enabled it. Opt-in hardening settings are
  left in place on delete, because silently weakening an account is worse than
  leaving a safer setting on.

This file is deployed inline (no S3 assets), so it uses only the standard
library and boto3, and sends the CloudFormation response itself.
"""

import json
import logging
import urllib.request

import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

INSPECTOR_TYPES = ["EC2", "ECR", "LAMBDA"]
MARKER_ENABLED_BY_STACK = "inspector-enabled-by-stack"


def _flag(props, key):
    return str(props.get(key, "false")).lower() == "true"


def send_response(event, context, status, data=None, physical_id=None, reason=None):
    body = json.dumps(
        {
            "Status": status,
            "Reason": (reason or "See CloudWatch Logs: " + getattr(context, "log_stream_name", "n/a"))[:1000],
            "PhysicalResourceId": physical_id or event.get("PhysicalResourceId") or "securitystack-settings",
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": False,
            "Data": data or {},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        event["ResponseURL"],
        data=body,
        method="PUT",
        headers={"Content-Type": "", "Content-Length": str(len(body))},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - URL is the CloudFormation presigned S3 URL
        LOG.info("CloudFormation response sent: %s %s", status, resp.status)


def inspector_enabled(client, account_id):
    resp = client.batch_get_account_status(accountIds=[account_id])
    accounts = resp.get("accounts", [])
    if not accounts:
        return False
    status = accounts[0].get("state", {}).get("status")
    return status in ("ENABLED", "ENABLING")


def enable_inspector(region, account_id):
    """Enable Inspector. Returns True if this call turned it on (so delete may undo it)."""
    client = boto3.client("inspector2", region_name=region)
    if inspector_enabled(client, account_id):
        LOG.info("Inspector already enabled in %s; leaving ownership with the account", region)
        return False
    client.enable(resourceTypes=INSPECTOR_TYPES)
    return True


def disable_inspector(region):
    client = boto3.client("inspector2", region_name=region)
    client.disable(resourceTypes=INSPECTOR_TYPES)


def enable_ebs_default_encryption(region):
    ec2 = boto3.client("ec2", region_name=region)
    if ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        return "already-enabled"
    ec2.enable_ebs_encryption_by_default()
    return "enabled"


def enable_account_s3_bpa(account_id):
    s3control = boto3.client("s3control")
    s3control.put_public_access_block(
        AccountId=account_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return "enabled"


def apply_settings(props, region, account_id, previously_enabled_by_stack=False):
    """Create/Update. Returns (physical_id, data)."""
    data = {}
    enabled_by_stack = previously_enabled_by_stack

    if _flag(props, "EnableInspector"):
        if enable_inspector(region, account_id):
            enabled_by_stack = True
        data["Inspector"] = "enabled"
    else:
        if previously_enabled_by_stack:
            disable_inspector(region)
            enabled_by_stack = False
        data["Inspector"] = "not-managed"

    if _flag(props, "AutoFixEbsDefaultEncryption"):
        data["EbsDefaultEncryption"] = enable_ebs_default_encryption(region)

    if _flag(props, "AutoFixS3AccountBlockPublicAccess"):
        data["S3AccountBlockPublicAccess"] = enable_account_s3_bpa(account_id)

    physical_id = "securitystack-settings-" + region
    if enabled_by_stack:
        physical_id += "|" + MARKER_ENABLED_BY_STACK
    return physical_id, data


def handler(event, context):
    LOG.info("Event: %s", json.dumps({k: v for k, v in event.items() if k != "ResponseURL"}))
    request_type = event["RequestType"]
    props = event.get("ResourceProperties", {})
    region = props.get("Region") or boto3.session.Session().region_name
    account_id = props.get("AccountId") or event["StackId"].split(":")[4]
    old_physical = event.get("PhysicalResourceId", "")
    owned = MARKER_ENABLED_BY_STACK in old_physical

    try:
        if request_type == "Delete":
            if owned:
                try:
                    disable_inspector(region)
                except Exception:  # best effort: never leave the stack stuck in DELETE_FAILED
                    LOG.exception("Could not disable Inspector during delete")
            send_response(event, context, "SUCCESS", physical_id=old_physical)
            return

        physical_id, data = apply_settings(props, region, account_id, previously_enabled_by_stack=owned)
        send_response(event, context, "SUCCESS", data=data, physical_id=physical_id)
    except Exception as exc:
        LOG.exception("Settings failed")
        send_response(event, context, "FAILED", reason=f"{type(exc).__name__}: {exc}")
