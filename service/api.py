"""SecurityStack free-scan API (API Gateway HTTP API -> Lambda).

Routes (served same-origin behind CloudFront under /api):
    POST /api/scans                  start a session: returns scanId, externalId, role launch link
    POST /api/scans/{scanId}/start   body {"roleArn": "..."}: queue the scan
    GET  /api/scans/{scanId}         status, and the result once finished

Security model:
* No credentials are ever sent to us. The visitor creates a read-only role
  (AWS-managed SecurityAudit policy) that trusts only our worker role, and only
  with the External ID generated for this scan. That stops "confused deputy"
  abuse: nobody can point us at someone else's account.
* scanId is a 192-bit random token and is the only handle on a scan.
* A scan can be started at most MAX_ATTEMPTS times; all data expires after 24h.
"""

import json
import os
import re
import secrets
import time
import urllib.parse

import boto3
from botocore.exceptions import ClientError

TABLE = os.environ.get("TABLE_NAME", "")
RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
WORKER_FUNCTION = os.environ.get("WORKER_FUNCTION", "")
WORKER_ROLE_ARN = os.environ.get("WORKER_ROLE_ARN", "")
SCAN_ROLE_TEMPLATE_URL = os.environ.get("SCAN_ROLE_TEMPLATE_URL", "")
TTL_SECONDS = 24 * 3600
MAX_ATTEMPTS = 3

ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role/SecurityStackScanRole[A-Za-z0-9+=,.@_-]{0,40}$")
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")

_ddb = boto3.resource("dynamodb")
_s3 = boto3.client("s3")
_lambda = boto3.client("lambda")


def _resp(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(body),
    }


def _table():
    return _ddb.Table(TABLE)


def role_launch_url(external_id, region):
    params = {
        "stackName": "SecurityStackScanRole",
        "templateURL": SCAN_ROLE_TEMPLATE_URL,
        "param_ExternalId": external_id,
        "param_ScannerRoleArn": WORKER_ROLE_ARN,
    }
    return (
        f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}"
        f"#/stacks/quickcreate?{urllib.parse.urlencode(params)}"
    )


def create_scan(body):
    region = body.get("homeRegion") or "us-east-1"
    if not REGION_RE.match(region):
        return _resp(400, {"error": "Invalid region."})
    scan_id = secrets.token_urlsafe(24)  # 32 chars
    external_id = "ss-" + secrets.token_urlsafe(24)
    now = int(time.time())
    _table().put_item(
        Item={
            "scanId": scan_id,
            "externalId": external_id,
            "homeRegion": region,
            "status": "AWAITING_ROLE",
            "attempts": 0,
            "createdAt": now,
            "ttl": now + TTL_SECONDS,
        },
        ConditionExpression="attribute_not_exists(scanId)",
    )
    return _resp(201, {
        "scanId": scan_id,
        "externalId": external_id,
        "homeRegion": region,
        "roleLaunchUrl": role_launch_url(external_id, region),
        "scannerRoleArn": WORKER_ROLE_ARN,
    })


def start_scan(scan_id, body):
    role_arn = (body.get("roleArn") or "").strip()
    if not ROLE_ARN_RE.match(role_arn):
        return _resp(400, {"error": "That doesn't look like the RoleArn output of the SecurityStackScanRole stack."})
    try:
        _table().update_item(
            Key={"scanId": scan_id},
            UpdateExpression="SET #s = :queued, roleArn = :arn, attempts = attempts + :one, errorMessage = :empty",
            ConditionExpression="attribute_exists(scanId) AND #s IN (:awaiting, :failed) AND attempts < :max",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":queued": "QUEUED", ":arn": role_arn, ":one": 1, ":empty": "",
                ":awaiting": "AWAITING_ROLE", ":failed": "FAILED", ":max": MAX_ATTEMPTS,
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return _resp(409, {"error": "This scan can't be started (unknown, already running, or out of retries). Start a new scan."})
        raise
    _lambda.invoke(FunctionName=WORKER_FUNCTION, InvocationType="Event", Payload=json.dumps({"scanId": scan_id}).encode())
    return _resp(202, {"scanId": scan_id, "status": "QUEUED"})


def get_scan(scan_id):
    item = _table().get_item(Key={"scanId": scan_id}).get("Item")
    if not item:
        return _resp(404, {"error": "Scan not found or expired."})
    out = {"scanId": scan_id, "status": item["status"], "homeRegion": item.get("homeRegion")}
    if item.get("errorMessage"):
        out["error"] = item["errorMessage"]
    if item["status"] == "DONE":
        obj = _s3.get_object(Bucket=RESULTS_BUCKET, Key=f"results/{scan_id}.json")
        out["result"] = json.loads(obj["Body"].read())
    return _resp(200, out)


def handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path = event.get("rawPath", "")
    scan_id = (event.get("pathParameters") or {}).get("scanId")
    try:
        body = json.loads(event.get("body") or "{}") if method == "POST" else {}
        if not isinstance(body, dict):
            raise ValueError
    except ValueError:
        return _resp(400, {"error": "Body must be a JSON object."})

    if scan_id is not None and not SCAN_ID_RE.match(scan_id):
        return _resp(404, {"error": "Scan not found or expired."})

    if method == "POST" and path.rstrip("/") == "/api/scans":
        return create_scan(body)
    if method == "POST" and scan_id and path.endswith("/start"):
        return start_scan(scan_id, body)
    if method == "GET" and scan_id:
        return get_scan(scan_id)
    return _resp(404, {"error": "Not found."})
