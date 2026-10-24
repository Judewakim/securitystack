#!/usr/bin/env python3
"""Build the one-click release templates from the CDK app.

    python3 scripts/build_release.py

Runs `cdk synth`, then strips CDK-only metadata (construct paths, cdk-nag
suppression records, the CDKMetadata resource) so customers get a clean,
readable template. Output: dist/securitystack-home.template.json and
dist/securitystack-region.template.json.

The same templates are what CI uploads to the public template bucket behind the
"Launch Stack" buttons.
"""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "dist"
STACKS = {"SecurityStackHome": "securitystack-home", "SecurityStackRegion": "securitystack-region"}
MAX_S3_TEMPLATE_BYTES = 1_000_000  # CloudFormation limit for templates loaded from S3


def clean(template: dict) -> dict:
    template.get("Resources", {}).pop("CDKMetadata", None)
    template.get("Conditions", {}).pop("CDKMetadataAvailable", None)
    for res in template.get("Resources", {}).values():
        meta = res.get("Metadata")
        if meta:
            for key in ("aws:cdk:path", "cdk_nag", "aws:asset:path", "aws:asset:property"):
                meta.pop(key, None)
            if not meta:
                res.pop("Metadata")
    # BootstraplessSynthesizer adds no BootstrapVersion rule/parameter, but be safe.
    template.get("Parameters", {}).pop("BootstrapVersion", None)
    template.get("Rules", {}).pop("CheckBootstrapVersion", None)
    if "Rules" in template and not template["Rules"]:
        template.pop("Rules")
    return template


def main() -> int:
    subprocess.run(["cdk", "synth", "--quiet", "-c", "release=true", "-o", str(ROOT / "cdk.out" )], cwd=ROOT, check=True)
    OUT.mkdir(exist_ok=True)
    for stack, name in STACKS.items():
        src = ROOT / "cdk.out" / f"{stack}.template.json"
        template = clean(json.loads(src.read_text()))
        body = json.dumps(template, indent=1)
        if len(body.encode()) > MAX_S3_TEMPLATE_BYTES:
            print(f"{name}: template too large ({len(body)} bytes)", file=sys.stderr)
            return 1
        dest = OUT / f"{name}.template.json"
        dest.write_text(body + "\n")
        print(f"wrote {dest.relative_to(ROOT)} ({len(body):,} bytes, {len(template['Resources'])} resources)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
