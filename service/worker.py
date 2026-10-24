"""SecurityStack scan worker: assumes the visitor's read-only role and runs the scan.

Invoked asynchronously by the API with {"scanId": ...}. Writes the result to S3
(deleted after 1 day by a lifecycle rule) and updates the scan's status.
"""

import json
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError

from scanner import run_scan

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

TABLE = os.environ.get("TABLE_NAME", "")
RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
BASELINE_TEMPLATE_URL = os.environ.get("BASELINE_TEMPLATE_URL", "")

_ddb = boto3.resource("dynamodb")
_s3 = boto3.client("s3")
_sts = boto3.client("sts")

FRIENDLY = {
    "AccessDenied": "We couldn't use the role. Make sure you created it from this scan's link, the stack shows "
                    "CREATE_COMPLETE, and you pasted its RoleArn output exactly.",
}


def _set_status(scan_id, status, **extra):
    names = {"#s": "status"}
    values = {":s": status, ":t": int(time.time())}
    sets = ["#s = :s", "updatedAt = :t"]
    for i, (k, v) in enumerate(extra.items()):
        names[f"#k{i}"] = k
        values[f":v{i}"] = v
        sets.append(f"#k{i} = :v{i}")
    _ddb.Table(TABLE).update_item(
        Key={"scanId": scan_id},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def assume(role_arn, external_id, scan_id):
    creds = _sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"securitystack-scan-{scan_id[:8]}",
        ExternalId=external_id,
        DurationSeconds=3600,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def handler(event, context):
    scan_id = event["scanId"]
    item = _ddb.Table(TABLE).get_item(Key={"scanId": scan_id}).get("Item")
    if not item or item.get("status") != "QUEUED":
        LOG.warning("Scan %s not runnable (status=%s)", scan_id, item and item.get("status"))
        return

    _set_status(scan_id, "RUNNING")
    try:
        session = assume(item["roleArn"], item["externalId"], scan_id)
        result = run_scan(session, home_region=item.get("homeRegion", "us-east-1"), baseline_template_url=BASELINE_TEMPLATE_URL)
        expected_account = item["roleArn"].split(":")[4]
        if result["accountId"] != expected_account:  # defense in depth
            raise RuntimeError("Account mismatch")
        _s3.put_object(
            Bucket=RESULTS_BUCKET,
            Key=f"results/{scan_id}.json",
            Body=json.dumps(result).encode("utf-8"),
            ContentType="application/json",
        )
        _set_status(scan_id, "DONE", score=result["score"], grade=result["grade"])
        LOG.info("Scan %s done: account %s score %s", scan_id, result["accountId"], result["score"])
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Error")
        LOG.warning("Scan %s failed: %s", scan_id, code)
        _set_status(scan_id, "FAILED", errorMessage=FRIENDLY.get(code, f"The scan failed ({code}). You can retry."))
    except Exception:
        LOG.exception("Scan %s crashed", scan_id)
        _set_status(scan_id, "FAILED", errorMessage="The scan hit an unexpected error. You can retry.")
