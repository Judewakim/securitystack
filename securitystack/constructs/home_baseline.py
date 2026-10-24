"""HomeBaseline: the account-wide pieces SecurityStack deploys once, in the home region.

* A central, locked-down log bucket for CloudTrail and AWS Config (all regions).
* A multi-region CloudTrail trail.
* Security Hub cross-region aggregation, so one place sees every region.
* Real-time email alerts for new HIGH/CRITICAL findings.
* A weekly digest: posture score + top issues, as an email and an HTML report.
"""

from aws_cdk import (
    Aws,
    CfnCondition,
    CfnOutput,
    CfnParameter,
    Duration,
    Fn,
    RemovalPolicy,
    aws_cloudtrail as cloudtrail,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_s3 as s3,
    aws_securityhub as securityhub,
    aws_sns as sns,
)
from cdk_nag import NagSuppressions
from constructs import Construct

from ._util import RUNTIME, bool_param, inline_source, is_true

TRAIL_NAME = "securitystack-trail"


class HomeBaseline(Construct):
    def __init__(self, scope: Construct, id_: str) -> None:
        super().__init__(scope, id_)

        p_email = CfnParameter(
            self,
            "AlertEmail",
            type="String",
            default="",
            allowed_pattern=r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$",
            constraint_description="Must be a valid email address or empty.",
            description="Email for real-time HIGH/CRITICAL alerts and the weekly report. You must confirm the subscription email AWS sends.",
        )
        p_email.override_logical_id("AlertEmail")
        p_trail = bool_param(
            self, "CreateTrail", default=True,
            description="Create a multi-region CloudTrail trail. Set false if you already have one (a second copy of management events is billed).",
        )
        p_retention = CfnParameter(
            self,
            "LogRetentionDays",
            type="Number",
            default=365,
            min_value=90,
            max_value=3650,
            description="Days to keep CloudTrail and Config logs before deletion (moved to cheaper storage after 30/90 days).",
        )
        p_retention.override_logical_id("LogRetentionDays")
        self.p_s3_bpa = bool_param(
            self, "AutoFixS3AccountBlockPublicAccess", default=False,
            description="OPT-IN auto-fix: turn on account-wide S3 Block Public Access. WARNING: breaks any bucket intentionally serving public content.",
        )
        self.params = [p_email, p_trail, p_retention, self.p_s3_bpa]

        c_email = CfnCondition(self, "HasAlertEmail", expression=Fn.condition_not(Fn.condition_equals(p_email.value_as_string, "")))
        c_email.override_logical_id("HasAlertEmail")
        c_trail = is_true(self, "TrailOn", p_trail)

        # --- Buckets ---------------------------------------------------------------
        access_logs = s3.Bucket(
            self,
            "AccessLogsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,  # required for S3 server access logging
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(365))],
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.log_bucket = s3.Bucket(
            self,
            "LogBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            server_access_logs_bucket=access_logs,
            server_access_logs_prefix="log-bucket/",
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="TierThenExpire",
                    transitions=[
                        s3.Transition(storage_class=s3.StorageClass.INFREQUENT_ACCESS, transition_after=Duration.days(30)),
                        s3.Transition(storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL, transition_after=Duration.days(90)),
                    ],
                    expiration=Duration.days(p_retention.value_as_number),
                    noncurrent_version_expiration=Duration.days(30),
                    abort_incomplete_multipart_upload_after=Duration.days(7),
                )
            ],
            # Logs are audit evidence: keep them if the stack is deleted.
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.reports_bucket = s3.Bucket(
            self,
            "ReportsBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            server_access_logs_bucket=access_logs,
            server_access_logs_prefix="reports-bucket/",
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(730))],
            removal_policy=RemovalPolicy.RETAIN,
        )

        bucket_arn = self.log_bucket.bucket_arn
        trail_arn = f"arn:{Aws.PARTITION}:cloudtrail:{Aws.REGION}:{Aws.ACCOUNT_ID}:trail/{TRAIL_NAME}"
        # CloudTrail writes here (confused-deputy protection via SourceArn).
        self.log_bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="CloudTrailAclCheck",
            principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
            actions=["s3:GetBucketAcl"],
            resources=[bucket_arn],
            conditions={"StringEquals": {"aws:SourceArn": trail_arn}},
        ))
        self.log_bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="CloudTrailWrite",
            principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
            actions=["s3:PutObject"],
            resources=[f"{bucket_arn}/cloudtrail/AWSLogs/{Aws.ACCOUNT_ID}/*"],
            conditions={"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": trail_arn}},
        ))
        # AWS Config in every region writes here (only for this account).
        self.log_bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="ConfigAclCheck",
            principals=[iam.ServicePrincipal("config.amazonaws.com")],
            actions=["s3:GetBucketAcl", "s3:ListBucket"],
            resources=[bucket_arn],
            conditions={"StringEquals": {"aws:SourceAccount": Aws.ACCOUNT_ID}},
        ))
        self.log_bucket.add_to_resource_policy(iam.PolicyStatement(
            sid="ConfigWrite",
            principals=[iam.ServicePrincipal("config.amazonaws.com")],
            actions=["s3:PutObject"],
            resources=[f"{bucket_arn}/config/AWSLogs/{Aws.ACCOUNT_ID}/Config/*"],
            conditions={"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceAccount": Aws.ACCOUNT_ID}},
        ))

        # --- CloudTrail: who did what, in every region ----------------------------
        trail = cloudtrail.CfnTrail(
            self,
            "Trail",
            trail_name=TRAIL_NAME,
            s3_bucket_name=self.log_bucket.bucket_name,
            s3_key_prefix="cloudtrail",
            is_logging=True,
            is_multi_region_trail=True,
            include_global_service_events=True,
            enable_log_file_validation=True,
        )
        trail.cfn_options.condition = c_trail
        trail.add_resource_dependency(self.log_bucket.policy.node.default_child)

        # --- Alerts ----------------------------------------------------------------
        self.topic = sns.Topic(self, "AlertsTopic", display_name="SecurityStack alerts", enforce_ssl=True)
        sub = sns.CfnSubscription(
            self, "AlertEmailSubscription", topic_arn=self.topic.topic_arn, protocol="email", endpoint=p_email.value_as_string
        )
        sub.cfn_options.condition = c_email

        alert_rule = events.Rule(
            self,
            "HighSeverityAlertRule",
            description="SecurityStack: email new, active HIGH/CRITICAL Security Hub findings",
            event_pattern=events.EventPattern(
                source=["aws.securityhub"],
                detail_type=["Security Hub Findings - Imported"],
                detail={
                    "findings": {
                        "Severity": {"Label": ["HIGH", "CRITICAL"]},
                        "Workflow": {"Status": ["NEW"]},
                        "RecordState": ["ACTIVE"],
                        "Compliance": {"Status": [{"anything-but": ["PASSED"]}]},
                    }
                },
            ),
        )
        # Alternate pattern: threat findings (GuardDuty, Inspector) carry no Compliance block.
        threat_rule = events.Rule(
            self,
            "HighSeverityThreatRule",
            description="SecurityStack: email new HIGH/CRITICAL threat and vulnerability findings",
            event_pattern=events.EventPattern(
                source=["aws.securityhub"],
                detail_type=["Security Hub Findings - Imported"],
                detail={
                    "findings": {
                        "Severity": {"Label": ["HIGH", "CRITICAL"]},
                        "Workflow": {"Status": ["NEW"]},
                        "RecordState": ["ACTIVE"],
                        "Compliance": {"Status": [{"exists": False}]},
                    }
                },
            ),
        )
        message = events.RuleTargetInput.from_multiline_text(
            "SecurityStack alert ("
            + events.EventField.from_path("$.detail.findings[0].Severity.Label")
            + ")\n\n"
            + events.EventField.from_path("$.detail.findings[0].Title")
            + "\n\nAccount: "
            + events.EventField.from_path("$.detail.findings[0].AwsAccountId")
            + "\nRegion: "
            + events.EventField.from_path("$.detail.findings[0].Region")
            + "\nResource: "
            + events.EventField.from_path("$.detail.findings[0].Resources[0].Id")
            + "\n\nWhat it means: "
            + events.EventField.from_path("$.detail.findings[0].Description")
            + "\n\nOpen Security Hub in the AWS console to see full details and remediation steps."
        )
        for rule in (alert_rule, threat_rule):
            rule.add_target(targets.SnsTopic(self.topic, message=message))

        # --- Weekly digest -------------------------------------------------------------
        digest_logs = logs.LogGroup(self, "DigestLogs", retention=logs.RetentionDays.ONE_YEAR)
        digest_role = iam.Role(
            self, "DigestRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="SecurityStack weekly digest: read Security Hub findings, write the report, send the email.",
        )
        digest_logs.grant_write(digest_role)
        digest_role.add_to_policy(iam.PolicyStatement(actions=["securityhub:GetFindings"], resources=["*"]))
        self.reports_bucket.grant_put(digest_role, "reports/*")
        self.topic.grant_publish(digest_role)

        digest = lambda_.Function(
            self,
            "DigestFunction",
            runtime=RUNTIME,
            handler="index.handler",
            code=lambda_.Code.from_inline(inline_source("digest")),
            timeout=Duration.minutes(5),
            memory_size=512,
            role=digest_role,
            log_group=digest_logs,
            environment={"REPORTS_BUCKET": self.reports_bucket.bucket_name, "TOPIC_ARN": self.topic.topic_arn},
            description="SecurityStack weekly posture report",
        )
        events.Rule(
            self,
            "WeeklyDigestSchedule",
            description="SecurityStack weekly report (Mondays 13:00 UTC)",
            schedule=events.Schedule.cron(minute="0", hour="13", week_day="MON"),
            targets=[targets.LambdaFunction(digest)],
        )
        self.digest_function = digest

        CfnOutput(self, "LogBucketName", value=self.log_bucket.bucket_name,
                  description="Pass this as ConfigBucketName when you add SecurityStack to another region.").override_logical_id("LogBucketName")
        CfnOutput(self, "ReportsBucketName", value=self.reports_bucket.bucket_name,
                  description="Weekly reports are written under reports/weekly/.").override_logical_id("ReportsBucketName")
        CfnOutput(self, "DigestFunctionName", value=digest.function_name,
                  description="Run this Lambda once to generate a report right away.").override_logical_id("DigestFunctionName")

        # --- Documented cdk-nag exceptions ---------------------------------------------
        NagSuppressions.add_resource_suppressions(
            access_logs,
            [{"id": "AwsSolutions-S1", "reason": "This is the server-access-log destination; logging it to itself would loop."}],
        )
        NagSuppressions.add_resource_suppressions(
            self.topic,
            [{"id": "AwsSolutions-SNS2", "reason": "Messages contain finding titles only. A customer-managed KMS key would add cost; the AWS-managed SNS key cannot be used with EventBridge targets."}],
        )
        NagSuppressions.add_resource_suppressions(
            digest_role,
            [{"id": "AwsSolutions-IAM5", "reason": "securityhub:GetFindings does not support resource-level permissions; S3 write is scoped to the reports/ prefix.", "appliesTo": ["Resource::*", {"regex": "/^Action::s3:.*$/"}, {"regex": "/^Resource::<.*ReportsBucket.*\\.Arn>/reports/\\*$/"}]}],
            apply_to_children=True,
        )

    def add_finding_aggregator(self, hub: securityhub.CfnHub, condition: CfnCondition) -> None:
        """Pull findings from every region into the home region (needs the home hub)."""
        aggregator = securityhub.CfnFindingAggregator(self, "FindingAggregator", region_linking_mode="ALL_REGIONS")
        aggregator.cfn_options.condition = condition
        aggregator.add_resource_dependency(hub)
