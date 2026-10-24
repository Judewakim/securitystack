#!/usr/bin/env python3
"""Detect which baseline services already exist, and print matching CDK parameters.

CloudFormation can't adopt an existing GuardDuty detector, Security Hub, Config
recorder or account analyzer: creating a second one fails the whole stack. This
script looks first and switches those off, exactly like the free scan does for
its Launch Stack link.

    python3 scripts/preflight.py --region us-east-1 [--stack SecurityStackHome]
    -> --parameters SecurityStackHome:EnableGuardDuty=false ...

In CI it runs with the CDK bootstrap *lookup* role (read-only), so the deploy
role needs no extra permissions. Anything it can't determine is switched OFF:
skipping a service is safe, a failed stack is not.
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError


def detect(session, region):
    """Return {param: "true"/"false"} for the regional switches + CreateTrail."""
    found = {}

    def check(param, fn):
        try:
            found[param] = "false" if fn() else "true"
        except ClientError as e:
            print(f"preflight: couldn't check {param} ({e.response['Error']['Code']}); leaving it off", file=sys.stderr)
            found[param] = "false"

    gd = session.client("guardduty", region_name=region)
    check("EnableGuardDuty", lambda: bool(gd.list_detectors()["DetectorIds"]))

    sh = session.client("securityhub", region_name=region)

    def hub_exists():
        try:
            sh.describe_hub()
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidAccessException", "ResourceNotFoundException"):
                return False
            raise

    check("EnableSecurityHub", hub_exists)

    cfg = session.client("config", region_name=region)
    check("EnableConfigRecorder", lambda: bool(cfg.describe_configuration_recorders()["ConfigurationRecorders"]))

    aa = session.client("accessanalyzer", region_name=region)
    check("EnableAccessAnalyzer", lambda: bool(aa.list_analyzers(type="ACCOUNT")["analyzers"]))

    ct = session.client("cloudtrail", region_name=region)
    check("CreateTrail", lambda: any(t.get("IsMultiRegionTrail") for t in ct.describe_trails(includeShadowTrails=True)["trailList"]))
    return found


def lookup_session(region):
    """Assume the CDK bootstrap lookup role (ReadOnlyAccess) if we can; else use our own identity."""
    base = boto3.Session(region_name=region)
    account = base.client("sts").get_caller_identity()["Account"]
    role = f"arn:aws:iam::{account}:role/cdk-hnb659fds-lookup-role-{account}-{region}"
    try:
        c = base.client("sts").assume_role(RoleArn=role, RoleSessionName="securitystack-preflight")["Credentials"]
        return boto3.Session(
            aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
            aws_session_token=c["SessionToken"], region_name=region,
        )
    except ClientError:
        return base


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", required=True)
    ap.add_argument("--stack", default="SecurityStackHome")
    args = ap.parse_args(argv)
    found = detect(lookup_session(args.region), args.region)
    for k, v in found.items():
        print(f"preflight: {k}={v}", file=sys.stderr)
    print(" ".join(f"--parameters {args.stack}:{k}={v}" for k, v in found.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
