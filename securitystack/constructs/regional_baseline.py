"""RegionalBaseline: the security services SecurityStack turns on in each region.

A single custom resource (lambdas/baseline) does the enabling, because
CloudFormation's native resources fail when a service is already on, and most
real accounts already run some of these. It turns on only what's missing and,
on delete, removes only what it turned on. That makes the stack genuinely
one-click: no need to know which services already exist.
"""

from aws_cdk import (
    Aws,
    CfnParameter,
    CustomResource,
    Duration,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
)
from cdk_nag import NagSuppressions
from constructs import Construct, IConstruct

from ._util import RUNTIME, bool_param, inline_source

SERVICE_LINKED = [
    "guardduty.amazonaws.com",
    "malware-protection.guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "inspector2.amazonaws.com",
    "agentless.inspector2.amazonaws.com",
    "access-analyzer.amazonaws.com",
]


class RegionalBaseline(Construct):
    def __init__(
        self,
        scope: Construct,
        id_: str,
        *,
        log_bucket_name: str,
        is_home_region: bool,
        home_props: dict | None = None,
        depends_on: list[IConstruct] | None = None,
    ) -> None:
        super().__init__(scope, id_)

        def manage(name, label, cost_note=""):
            return bool_param(
                self, f"Enable{name}", default=True,
                description=f"Turn on {label} if it isn't on yet. If it's already running it is left exactly as it is.{cost_note}",
            )

        p_guardduty = manage("GuardDuty", "GuardDuty threat detection")
        p_securityhub = manage("SecurityHub", "Security Hub with the AWS Foundational and CIS v3.0 standards")
        p_config = manage("ConfigRecorder", "the AWS Config recorder")
        p_analyzer = manage("AccessAnalyzer", "IAM Access Analyzer (free)")
        p_inspector = manage("Inspector", "Amazon Inspector for EC2, ECR and Lambda", " Billed per resource scanned.")
        p_ebs = bool_param(
            self, "AutoFixEbsDefaultEncryption", default=False,
            description="OPT-IN auto-fix: turn on EBS encryption by default in this region (affects new volumes only).",
        )
        self.params: list[CfnParameter] = [p_guardduty, p_securityhub, p_config, p_analyzer, p_inspector, p_ebs]

        # --- Role AWS Config records with (only used if Config isn't already on) ----
        bucket_arn = f"arn:{Aws.PARTITION}:s3:::{log_bucket_name}"
        config_role = iam.Role(
            self,
            "ConfigRole",
            assumed_by=iam.ServicePrincipal("config.amazonaws.com", conditions={"StringEquals": {"aws:SourceAccount": Aws.ACCOUNT_ID}}),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWS_ConfigRole")],
            description="Lets AWS Config record resource configuration (SecurityStack).",
        )
        # AWS_ConfigRole has no S3 write access; Config writes with this role.
        config_delivery = iam.Policy(
            self,
            "ConfigDeliveryPolicy",
            policy_name="SecurityStackConfigDelivery",
            roles=[config_role],
            statements=[
                iam.PolicyStatement(actions=["s3:GetBucketAcl", "s3:ListBucket"], resources=[bucket_arn]),
                iam.PolicyStatement(
                    actions=["s3:PutObject"],
                    resources=[f"{bucket_arn}/config/AWSLogs/{Aws.ACCOUNT_ID}/Config/*"],
                    conditions={"StringLike": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                ),
            ],
        )

        # --- The baseline function ----------------------------------------------------
        log_group = logs.LogGroup(self, "BaselineLogs", retention=logs.RetentionDays.ONE_YEAR)
        role = iam.Role(
            self,
            "BaselineRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="SecurityStack: turn on missing security services, and only remove what it turned on.",
        )
        log_group.grant_write(role)
        role.add_to_policy(iam.PolicyStatement(
            sid="ManageSecurityServices",
            actions=[
                "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:CreateDetector",
                "guardduty:UpdateDetector", "guardduty:DeleteDetector",
                "securityhub:DescribeHub", "securityhub:EnableSecurityHub", "securityhub:DisableSecurityHub",
                "securityhub:GetEnabledStandards", "securityhub:BatchEnableStandards", "securityhub:BatchDisableStandards",
                "securityhub:ListFindingAggregators", "securityhub:CreateFindingAggregator", "securityhub:DeleteFindingAggregator",
                "config:DescribeConfigurationRecorders", "config:DescribeDeliveryChannels",
                "config:PutConfigurationRecorder", "config:PutDeliveryChannel",
                "config:StartConfigurationRecorder", "config:StopConfigurationRecorder",
                "config:DeleteConfigurationRecorder", "config:DeleteDeliveryChannel",
                "access-analyzer:ListAnalyzers", "access-analyzer:CreateAnalyzer", "access-analyzer:DeleteAnalyzer",
                "inspector2:Enable", "inspector2:Disable", "inspector2:BatchGetAccountStatus",
                "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
                "ec2:GetEbsEncryptionByDefault", "ec2:EnableEbsEncryptionByDefault",
                "s3:PutAccountPublicAccessBlock",
            ],
            resources=["*"],  # these APIs are account/region-level and don't accept resource ARNs
        ))
        role.add_to_policy(iam.PolicyStatement(
            sid="ManageOwnTrail",
            actions=["cloudtrail:CreateTrail", "cloudtrail:StartLogging", "cloudtrail:DeleteTrail"],
            resources=[f"arn:{Aws.PARTITION}:cloudtrail:{Aws.REGION}:{Aws.ACCOUNT_ID}:trail/securitystack-trail"],
        ))
        role.add_to_policy(iam.PolicyStatement(
            sid="ServiceLinkedRoles",
            actions=["iam:CreateServiceLinkedRole"],
            resources=[f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:role/aws-service-role/*"],
            conditions={"StringEquals": {"iam:AWSServiceName": SERVICE_LINKED}},
        ))
        role.add_to_policy(iam.PolicyStatement(
            sid="PassConfigRole",
            actions=["iam:PassRole"],
            resources=[config_role.role_arn],
            conditions={"StringEquals": {"iam:PassedToService": "config.amazonaws.com"}},
        ))
        role.add_to_policy(iam.PolicyStatement(
            sid="OwnershipLedger",
            actions=["ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter"],
            resources=[f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter/securitystack/*"],
        ))

        fn = lambda_.Function(
            self,
            "BaselineFunction",
            runtime=RUNTIME,
            handler="index.handler",
            code=lambda_.Code.from_inline(inline_source("baseline")),
            timeout=Duration.minutes(5),
            role=role,
            log_group=log_group,
            description="SecurityStack: turn on missing security services in this region",
        )

        props = {
            "Region": Aws.REGION,
            "Partition": Aws.PARTITION,
            "AccountId": Aws.ACCOUNT_ID,
            "IsHomeRegion": "true" if is_home_region else "false",
            "LogBucketName": log_bucket_name,
            "ConfigRoleArn": config_role.role_arn,
            "EnableGuardDuty": p_guardduty.value_as_string,
            "EnableSecurityHub": p_securityhub.value_as_string,
            "EnableConfigRecorder": p_config.value_as_string,
            "EnableAccessAnalyzer": p_analyzer.value_as_string,
            "EnableInspector": p_inspector.value_as_string,
            "AutoFixEbsDefaultEncryption": p_ebs.value_as_string,
            "Version": "3",
            **(home_props or {}),
        }
        self.resource = CustomResource(self, "Baseline", service_token=fn.function_arn, properties=props)
        # Create after (and delete before) the role, policies and bucket policy it relies on.
        for dep in [config_role, config_delivery, role, *(depends_on or [])]:
            self.resource.node.add_dependency(dep)

        NagSuppressions.add_resource_suppressions(role, [
            {"id": "AwsSolutions-IAM5", "reason": "GuardDuty, Security Hub, Config, Access Analyzer, Inspector, EBS-default and S3 account settings are account/region-level APIs without resource ARNs; service-linked role creation is limited by iam:AWSServiceName; SSM access is limited to the /securitystack/ prefix."},
        ], apply_to_children=True)
        NagSuppressions.add_resource_suppressions(config_delivery, [
            {"id": "AwsSolutions-IAM5", "reason": "Config writes one object per snapshot under its own AWSLogs/<account>/Config/ prefix; the wildcard is scoped to that prefix only."},
        ])
        NagSuppressions.add_resource_suppressions(config_role, [
            {"id": "AwsSolutions-IAM4", "reason": "AWS_ConfigRole is the AWS-maintained policy for the Config recorder."},
        ])
