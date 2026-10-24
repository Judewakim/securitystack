"""RegionalBaseline: the security services SecurityStack turns on in every region.

Everything here uses native CloudFormation resources where they exist (GuardDuty,
Security Hub, Config, IAM Access Analyzer). Only Inspector and two opt-in account
settings need a small custom resource, because CloudFormation has no resource
type for them.
"""

from aws_cdk import (
    Aws,
    CfnCondition,
    CfnParameter,
    CustomResource,
    Duration,
    Fn,
    aws_accessanalyzer as accessanalyzer,
    aws_config as config,
    aws_guardduty as guardduty,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_securityhub as securityhub,
)
from cdk_nag import NagSuppressions
from constructs import Construct

from ._util import RUNTIME, apply_condition, bool_param, inline_source, is_true

# Security Hub standard ARNs. Note "standards/" (plural): v1 used "standard/",
# which does not exist, so its standards were never enabled.
FSBP_ARN = "arn:${AWS::Partition}:securityhub:${AWS::Region}::standards/aws-foundational-security-best-practices/v/1.0.0"
CIS_V3_ARN = "arn:${AWS::Partition}:securityhub:${AWS::Region}::standards/cis-aws-foundations-benchmark/v/3.0.0"


class RegionalBaseline(Construct):
    """Turns on detection and posture services in one region.

    Every service can be switched off with a parameter, because CloudFormation
    cannot "adopt" something that already exists: if the account already has a
    GuardDuty detector, creating another one fails. The free scan detects what is
    already on and pre-fills these parameters in the Launch Stack link.
    """

    def __init__(
        self,
        scope: Construct,
        id_: str,
        *,
        config_bucket_name: str,
        is_home_region: bool,
        s3_account_bpa: str = "false",
    ) -> None:
        super().__init__(scope, id_)

        p_guardduty = bool_param(
            self, "EnableGuardDuty", default=True,
            description="Create a GuardDuty detector. Set false if GuardDuty is already on in this region.",
        )
        p_securityhub = bool_param(
            self, "EnableSecurityHub", default=True,
            description="Enable Security Hub with the AWS Foundational and CIS v3.0 standards. Set false if Security Hub is already on.",
        )
        p_config = bool_param(
            self, "EnableConfigRecorder", default=True,
            description="Create the AWS Config recorder. Set false if this region already has one (only one is allowed).",
        )
        p_analyzer = bool_param(
            self, "EnableAccessAnalyzer", default=True,
            description="Create an IAM Access Analyzer (free). Set false if this region already has an account analyzer.",
        )
        p_inspector = bool_param(
            self, "EnableInspector", default=True,
            description="Enable Amazon Inspector scanning for EC2, ECR and Lambda (billed per resource scanned).",
        )
        p_ebs = bool_param(
            self, "AutoFixEbsDefaultEncryption", default=False,
            description="OPT-IN auto-fix: turn on EBS encryption by default in this region (affects new volumes only).",
        )
        self.params: list[CfnParameter] = [p_guardduty, p_securityhub, p_config, p_analyzer, p_inspector, p_ebs]

        c_guardduty = is_true(self, "GuardDutyOn", p_guardduty)
        c_securityhub = is_true(self, "SecurityHubOn", p_securityhub)
        c_config = is_true(self, "ConfigOn", p_config)
        c_analyzer = is_true(self, "AccessAnalyzerOn", p_analyzer)
        self.securityhub_condition: CfnCondition = c_securityhub

        # --- GuardDuty: threat detection -------------------------------------------
        detector = guardduty.CfnDetector(
            self, "Detector", enable=True, finding_publishing_frequency="FIFTEEN_MINUTES"
        )
        detector.cfn_options.condition = c_guardduty

        # --- Security Hub: posture checks against FSBP + CIS v3.0 ------------------
        hub = securityhub.CfnHub(
            self,
            "Hub",
            enable_default_standards=False,  # we choose the standards explicitly below
            control_finding_generator="SECURITY_CONTROL",
            auto_enable_controls=True,
        )
        fsbp = securityhub.CfnStandard(self, "FoundationalStandard", standards_arn=Fn.sub(FSBP_ARN))
        cis = securityhub.CfnStandard(self, "CisV3Standard", standards_arn=Fn.sub(CIS_V3_ARN))
        self.hub = hub
        for std in (fsbp, cis):
            std.add_resource_dependency(hub)
        apply_condition(c_securityhub, hub, fsbp, cis)

        # --- AWS Config: resource inventory that Security Hub's checks depend on ---
        config_role = iam.CfnRole(
            self,
            "ConfigRole",
            assume_role_policy_document={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                        "Condition": {"StringEquals": {"aws:SourceAccount": Aws.ACCOUNT_ID}},
                    }
                ],
            },
            managed_policy_arns=[f"arn:{Aws.PARTITION}:iam::aws:policy/service-role/AWS_ConfigRole"],
            description="Lets AWS Config record resource configuration (SecurityStack).",
        )
        # AWS_ConfigRole has no S3 write access; for same-account delivery Config
        # writes with this role, so grant exactly the log bucket prefix it needs.
        bucket_arn = f"arn:{Aws.PARTITION}:s3:::{config_bucket_name}"
        config_delivery = iam.CfnPolicy(
            self,
            "ConfigDeliveryPolicy",
            policy_name="SecurityStackConfigDelivery",
            roles=[config_role.ref],
            policy_document={
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["s3:GetBucketAcl", "s3:ListBucket"], "Resource": bucket_arn},
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": f"{bucket_arn}/config/AWSLogs/{Aws.ACCOUNT_ID}/Config/*",
                        "Condition": {"StringLike": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                    },
                ],
            },
        )
        recorder = config.CfnConfigurationRecorder(
            self,
            "Recorder",
            role_arn=config_role.attr_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True,
                # Record global resources (IAM) only once, in the home region, to avoid
                # paying for the same items in every region.
                include_global_resource_types=is_home_region,
            ),
        )
        channel = config.CfnDeliveryChannel(
            self,
            "DeliveryChannel",
            s3_bucket_name=config_bucket_name,
            s3_key_prefix="config",
            config_snapshot_delivery_properties=config.CfnDeliveryChannel.ConfigSnapshotDeliveryPropertiesProperty(
                delivery_frequency="TwentyFour_Hours"
            ),
        )
        channel.add_resource_dependency(recorder)
        channel.add_resource_dependency(config_delivery)
        apply_condition(c_config, config_role, config_delivery, recorder, channel)

        # --- IAM Access Analyzer: flags resources shared outside the account -------
        analyzer = accessanalyzer.CfnAnalyzer(self, "AccessAnalyzer", type="ACCOUNT")
        analyzer.cfn_options.condition = c_analyzer

        # --- Settings custom resource: Inspector + opt-in auto-fixes ---------------
        settings_props = {
            "Region": Aws.REGION,
            "AccountId": Aws.ACCOUNT_ID,
            "EnableInspector": p_inspector.value_as_string,
            "AutoFixEbsDefaultEncryption": p_ebs.value_as_string,
            "AutoFixS3AccountBlockPublicAccess": s3_account_bpa,
            "Version": "2",
        }

        settings_log_group = logs.LogGroup(
            self, "SettingsLogs", retention=logs.RetentionDays.ONE_YEAR
        )
        settings_role = iam.Role(
            self,
            "SettingsRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="SecurityStack settings custom resource (Inspector, EBS default encryption, S3 account BPA).",
        )
        settings_log_group.grant_write(settings_role)
        settings_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "inspector2:Enable",
                    "inspector2:Disable",
                    "inspector2:BatchGetAccountStatus",
                    "ec2:GetEbsEncryptionByDefault",
                    "ec2:EnableEbsEncryptionByDefault",
                    "s3:PutAccountPublicAccessBlock",
                ],
                resources=["*"],  # these APIs are account-level and do not support resource ARNs
            )
        )
        settings_role.add_to_policy(
            iam.PolicyStatement(
                actions=["iam:CreateServiceLinkedRole"],
                resources=[f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:role/aws-service-role/inspector2.amazonaws.com/*"],
                conditions={"StringEquals": {"iam:AWSServiceName": "inspector2.amazonaws.com"}},
            )
        )
        settings_fn = lambda_.Function(
            self,
            "SettingsFunction",
            runtime=RUNTIME,
            handler="index.handler",
            code=lambda_.Code.from_inline(inline_source("settings")),
            timeout=Duration.minutes(2),
            role=settings_role,
            log_group=settings_log_group,
            description="SecurityStack: Inspector and opt-in account hardening settings",
        )
        self.settings = CustomResource(
            self, "Settings", service_token=settings_fn.function_arn, properties=settings_props
        )

        NagSuppressions.add_resource_suppressions(
            settings_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Inspector, EBS-default-encryption and S3 account BPA APIs are account-level and do not accept resource ARNs.",
                }
            ],
            apply_to_children=True,
        )
        NagSuppressions.add_resource_suppressions(
            config_delivery,
            [{"id": "AwsSolutions-IAM5", "reason": "Config writes one object per snapshot under its own AWSLogs/<account>/Config/ prefix; the wildcard is scoped to that prefix only.",
              "appliesTo": [{"regex": "/^Resource::arn:<AWS::Partition>:s3:::<.*>/config/AWSLogs/<AWS::AccountId>/Config/\\*$/"}]}],
        )
        NagSuppressions.add_resource_suppressions(
            config_role,
            [{"id": "AwsSolutions-IAM4", "reason": "AWS_ConfigRole is the AWS-maintained policy for the Config recorder."}],
        )
