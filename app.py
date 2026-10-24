#!/usr/bin/env python3
"""CDK entry point.

Baseline (customer account):
    cdk deploy SecurityStackHome -c homeRegion=us-east-1 --parameters AlertEmail=you@example.com
    cdk deploy SecurityStackRegion-us-west-2 -c regions=us-west-2 \
        --parameters SecurityStackRegion-us-west-2:ConfigBucketName=<LogBucketName output>

Free-scan service (the vendor's account; see docs/scan-service.md):
    cdk deploy SecurityStackScanService -c withService=true

Every stack is checked with cdk-nag (AWS Solutions rules) at synth time; synth
fails on any unsuppressed finding. Each suppression in the code carries a reason.
"""

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks

from securitystack.stacks import SecurityStackHome, SecurityStackRegion

app = cdk.App()

home_region = app.node.try_get_context("homeRegion")
extra_regions = [r for r in (app.node.try_get_context("regions") or "").split(",") if r]
account = app.node.try_get_context("account")


# Release build (scripts/build_release.py) -> no bootstrap rule/params in the template.
# CLI deploys -> default synthesizer, which can upload templates over 51 KB via the bootstrap bucket.
release = app.node.try_get_context("release") == "true"


def synth():
    return cdk.BootstraplessSynthesizer() if release else None


def env(region):
    # No region given -> environment-agnostic template (used for the one-click release).
    return cdk.Environment(account=account, region=region) if region else None


SecurityStackHome(app, "SecurityStackHome", env=env(home_region), synthesizer=synth())

if extra_regions:
    for region in extra_regions:
        SecurityStackRegion(app, f"SecurityStackRegion-{region}", env=env(region), synthesizer=synth())
else:
    SecurityStackRegion(app, "SecurityStackRegion", env=None, synthesizer=synth())

if app.node.try_get_context("withService") == "true":
    from securitystack.service_stack import ScanServiceStack

    ScanServiceStack(app, "SecurityStackScanService", env=env(home_region or "us-east-1"))

cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
app.synth()
