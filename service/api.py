"""SecurityStack free-scan API (API Gateway HTTP API -> Lambda).

Routes (served same-origin behind CloudFront under /api):
    POST /api/scans                  start a session: returns scanId, externalId, role launch link
    POST /api/scans/{scanId}/start   body {"roleArn": "..."}: queue the scan
    GET  /api/scans/{scanId}         status, and the result once finished

Security model:
* No credentials are ever sent to us. The visitor creates a read-only role that
  trusts only our worker role (fixed in the hosted template, not a parameter),
  and only with the External ID generated for this scan.
* Each scan gets its own role-name suffix, and /start only accepts a role whose
  name carries that suffix, so a role made for one scan can't be used by another.
* scanId is a 192-bit random token and is the only handle on a scan.
* Per-IP limits on creating and starting scans, on top of API Gateway throttling.
* Scan results are deleted within ~48h (S3 lifecycle + DynamoDB TTL).

Known limit: someone who tricks a person into creating the role from the
attacker's own scan link can see that person's results. The template and page
warn to only create the role from a scan you started yourself.
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
SCAN_ROLE_TEMPLATE_URL = os.environ.get("SCAN_ROLE_TEMPLATE_URL", "")
TTL_SECONDS = 24 * 3600
MAX_ATTEMPTS = 3
STALE_SECONDS = 15 * 60  # worker timeout is 10 min; a RUNNING scan older than this is dead
LIMITS = {"create": 20, "start": 10}  # per IP per hour

ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role/SecurityStackScanRole-([a-z0-9]{8})$")
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


def client_ip(event):
    """Viewer IP. Behind CloudFront, sourceIp is CloudFront's, and CloudFront appends
    the real viewer IP as the LAST X-Forwarded-For entry (earlier ones are client-supplied)."""
    xff = (event.get("headers") or {}).get("x-forwarded-for", "")
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    if parts:
        return parts[-1]
    return event.get("requestContext", {}).get("http", {}).get("sourceIp", "unknown")


def rate_limited(ip, action):
    hour = int(time.time() // 3600)
    try:
        _table().update_item(
            Key={"scanId": f"rate#{action}#{ip}#{hour}"},
            UpdateExpression="ADD hits :one SET #ttl = :ttl",
            ConditionExpression="attribute_not_exists(hits) OR hits < :max",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={":one": 1, ":max": LIMITS[action], ":ttl": (hour + 2) * 3600},
        )
        return False
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return True
        raise


def role_launch_url(external_id, suffix, region):
    params = {
        "stackName": f"SecurityStackScanRole-{suffix}",
        "templateURL": SCAN_ROLE_TEMPLATE_URL,
        "param_ExternalId": external_id,
        "param_ScanSuffix": suffix,
    }
    return (
        f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}"
        f"#/stacks/quickcreate?{urllib.parse.urlencode(params)}"
    )


def create_scan(body, ip):
    region = body.get("homeRegion") or "us-east-1"
    if not REGION_RE.match(region):
        return _resp(400, {"error": "Invalid region."})
    if rate_limited(ip, "create"):
        return _resp(429, {"error": "Too many scans from your network. Try again in an hour."})
    scan_id = secrets.token_urlsafe(24)  # 32 chars
    external_id = "ss-" + secrets.token_urlsafe(24)
    suffix = secrets.token_hex(4)  # 8 lowercase hex chars
    now = int(time.time())
    _table().put_item(
        Item={
            "scanId": scan_id,
            "externalId": external_id,
            "suffix": suffix,
            "homeRegion": region,
            "status": "AWAITING_ROLE",
            "attempts": 0,
            "createdAt": now,
            "updatedAt": now,
            "ttl": now + TTL_SECONDS,
        },
        ConditionExpression="attribute_not_exists(scanId)",
    )
    return _resp(201, {
        "scanId": scan_id,
        "homeRegion": region,
        "roleLaunchUrl": role_launch_url(external_id, suffix, region),
    })


def start_scan(scan_id, body, ip):
    role_arn = (body.get("roleArn") or "").strip()
    m = ROLE_ARN_RE.match(role_arn)
    if not m:
        return _resp(400, {"error": "That doesn't look like the RoleArn output of the SecurityStackScanRole stack."})
    if rate_limited(ip, "start"):
        return _resp(429, {"error": "Too many scans from your network. Try again in an hour."})
    now = int(time.time())
    try:
        _table().update_item(
            Key={"scanId": scan_id},
            UpdateExpression="SET #s = :queued, roleArn = :arn, attempts = attempts + :one, errorMessage = :empty, updatedAt = :now",
            ConditionExpression=(
                "attribute_exists(scanId) AND suffix = :suffix AND attempts < :max AND "
                "(#s IN (:awaiting, :failed) OR (#s IN (:queued, :running) AND updatedAt < :stale))"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":queued": "QUEUED", ":running": "RUNNING", ":arn": role_arn, ":one": 1, ":empty": "",
                ":awaiting": "AWAITING_ROLE", ":failed": "FAILED", ":max": MAX_ATTEMPTS,
                ":suffix": m.group(2), ":now": now, ":stale": now - STALE_SECONDS,
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return _resp(409, {"error": "This role or scan can't be used. Make sure you created the role from this scan's link, or start a new scan."})
        raise
    _lambda.invoke(FunctionName=WORKER_FUNCTION, InvocationType="Event", Payload=json.dumps({"scanId": scan_id}).encode())
    return _resp(202, {"scanId": scan_id, "status": "QUEUED"})


def get_scan(scan_id):
    item = _table().get_item(Key={"scanId": scan_id}).get("Item")
    if not item or int(item.get("ttl", 0)) < time.time():
        return _resp(404, {"error": "Scan not found or expired."})
    out = {"scanId": scan_id, "status": item["status"], "homeRegion": item.get("homeRegion")}
    if item.get("errorMessage"):
        out["error"] = item["errorMessage"]
    if item["status"] == "DONE":
        try:
            obj = _s3.get_object(Bucket=RESULTS_BUCKET, Key=f"results/{scan_id}.json")
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return _resp(404, {"error": "Scan not found or expired."})
            raise
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

    ip = client_ip(event)
    if method == "POST" and path.rstrip("/") == "/api/scans":
        return create_scan(body, ip)
    if method == "POST" and scan_id and path.endswith("/start"):
        return start_scan(scan_id, body, ip)
    if method == "GET" and scan_id:
        return get_scan(scan_id)
    return _resp(404, {"error": "Not found."})
