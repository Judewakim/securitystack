"""SecurityStack CloudFormation stacks.

* SecurityStackHome:   deploy once, in the region you work in most. Account-wide
                       logging, alerts and reports, plus the regional services.
* SecurityStackRegion: deploy in each additional region. Regional services only,
                       logging to the home region's bucket.

Neither stack uses S3 assets (Lambda code is inline), so the release build can use
the BootstraplessSynthesizer: customers launch the templates from a "Launch Stack"
link without installing or bootstrapping the CDK. Engineers deploying with the
CDK CLI get the normal bootstrapped synthesizer instead (see app.py).
"""

from aws_cdk import CfnParameter, Stack, Tags
from constructs import Construct

from . import __version__
from .constructs.home_baseline import HomeBaseline
from .constructs.regional_baseline import RegionalBaseline

DESCRIPTION = (
    "SecurityStack v{v} ({kind}): GuardDuty, Security Hub (AWS Foundational + CIS v3.0), "
    "AWS Config, IAM Access Analyzer and Inspector{extra}. "
    "Supports evidence for SOC 2 / ISO 27001 controls; does not by itself establish compliance."
)


def _interface(stack: Stack, groups: list[tuple[str, list[CfnParameter]]]) -> None:
    """Group parameters in the CloudFormation console so the form is easy to read."""
    stack.template_options.metadata = {
        "AWS::CloudFormation::Interface": {
            "ParameterGroups": [
                {"Label": {"default": label}, "Parameters": [p.logical_id for p in params]}
                for label, params in groups
            ]
        }
    }


class SecurityStackHome(Stack):
    def __init__(self, scope: Construct, id_: str, **kwargs) -> None:
        super().__init__(
            scope,
            id_,
            description=DESCRIPTION.format(
                v=__version__,
                kind="home region",
                extra=", plus multi-region CloudTrail, cross-region finding aggregation, email alerts and a weekly report",
            ),
            **kwargs,
        )
        home = HomeBaseline(self, "Home")
        regional = RegionalBaseline(
            self,
            "Regional",
            config_bucket_name=home.log_bucket.bucket_name,
            is_home_region=True,
            s3_account_bpa=home.p_s3_bpa.value_as_string,
        )
        home.add_finding_aggregator(regional.hub, regional.securityhub_condition)
        self.home, self.regional = home, regional

        _interface(self, [
            ("Alerts and logging", home.params[:3]),
            ("Services (set false for any already turned on in this region)", regional.params[:5]),
            ("Opt-in auto-fixes (off by default; these change existing settings)", [regional.params[5], home.p_s3_bpa]),
        ])
        Tags.of(self).add("securitystack", "home")


class SecurityStackRegion(Stack):
    def __init__(self, scope: Construct, id_: str, **kwargs) -> None:
        super().__init__(
            scope,
            id_,
            description=DESCRIPTION.format(v=__version__, kind="additional region", extra=""),
            **kwargs,
        )
        p_bucket = CfnParameter(
            self,
            "ConfigBucketName",
            type="String",
            allowed_pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$",
            description="LogBucketName output from your SecurityStack home stack.",
        )
        p_bucket.override_logical_id("ConfigBucketName")
        regional = RegionalBaseline(
            self, "Regional", config_bucket_name=p_bucket.value_as_string, is_home_region=False
        )
        self.regional = regional
        _interface(self, [
            ("Home stack", [p_bucket]),
            ("Services (set false for any already turned on in this region)", regional.params[:5]),
            ("Opt-in auto-fixes (off by default)", [regional.params[5]]),
        ])
        Tags.of(self).add("securitystack", "region")
