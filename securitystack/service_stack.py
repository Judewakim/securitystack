"""ScanServiceStack: the hosted free scan (deployed once, in the vendor's account).

    Browser ──► CloudFront ──► S3 (static site, private, OAC)
                   │
                   └─ /api/* ──► API Gateway HTTP API ──► API Lambda ──► DynamoDB (scan sessions, 24h TTL)
                                                              │
                                                              └─ async ──► Worker Lambda ── sts:AssumeRole + ExternalId ──► visitor's read-only role
                                                                               │
                                                                               └──► S3 results (deleted after 1 day)

    Templates bucket (public-read, templates/ only): scan-role.yaml and the
    release baseline templates, so "Launch Stack" links work.
"""

from pathlib import Path

from aws_cdk import (
    Aws,
    CfnOutput,
    Duration,
    Fn,
    RemovalPolicy,
    Stack,
    aws_apigatewayv2 as apigw,
    aws_apigatewayv2_integrations as integrations,
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
)
from cdk_nag import NagSuppressions
from constructs import Construct

from .constructs._util import RUNTIME

ROOT = Path(__file__).resolve().parents[1]
WORKER_ROLE_NAME = "SecurityStackScanWorker"
PLACEHOLDER_ARN = "arn:aws:iam::000000000000:role/SecurityStackScanWorker"

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; "
    "object-src 'none'; upgrade-insecure-requests"
)


class ScanServiceStack(Stack):
    def __init__(self, scope: Construct, id_: str, **kwargs) -> None:
        super().__init__(scope, id_, description="SecurityStack free scan service (web app + read-only scanner)", **kwargs)

        domain_name = self.node.try_get_context("domainName")  # e.g. securitystack.wakimworks.com
        certificate_arn = self.node.try_get_context("certificateArn")  # ACM cert in us-east-1

        # ---------------------------------------------------------------- storage
        access_logs = s3.Bucket(
            self, "AccessLogs",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,  # CloudFront standard logs need ACLs
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(90))],
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        table = dynamodb.TableV2(
            self, "Scans",
            partition_key=dynamodb.Attribute(name="scanId", type=dynamodb.AttributeType.STRING),
            billing=dynamodb.Billing.on_demand(),
            time_to_live_attribute="ttl",
            # No point-in-time backups: scan sessions must really be gone within ~48h.
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(point_in_time_recovery_enabled=False),
            removal_policy=RemovalPolicy.DESTROY,
        )

        results = s3.Bucket(
            self, "Results",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            server_access_logs_bucket=access_logs,
            server_access_logs_prefix="results/",
            lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(1))],  # scan results are short-lived
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # Public-read bucket for CloudFormation templates. CloudFormation "Launch Stack"
        # links require an S3 URL, so this one bucket is intentionally public — but
        # only objects under templates/, read-only, and nothing else is ever stored here.
        templates = s3.Bucket(
            self, "Templates",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=True, ignore_public_acls=True, block_public_policy=False, restrict_public_buckets=False
            ),
            enforce_ssl=True,
            versioned=True,
            server_access_logs_bucket=access_logs,
            server_access_logs_prefix="templates/",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        templates.add_to_resource_policy(iam.PolicyStatement(
            sid="PublicReadTemplatesOnly",
            principals=[iam.AnyPrincipal()],
            actions=["s3:GetObject"],
            resources=[templates.arn_for_objects("templates/*")],
        ))
        # The scan-role template trusts exactly this deployment's worker role. The ARN
        # is written into the published file, never left as a parameter, so the
        # trusted template can't be reused to grant access to anyone else.
        worker_role_arn = f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:role/{WORKER_ROLE_NAME}"
        scan_role_body = (ROOT / "templates" / "scan-role.yaml").read_text(encoding="utf-8")
        assert PLACEHOLDER_ARN in scan_role_body, "scan-role.yaml must contain the placeholder principal"
        scan_role_body = scan_role_body.replace(PLACEHOLDER_ARN, worker_role_arn)
        template_sources = [s3deploy.Source.data("scan-role.yaml", scan_role_body)]
        if (ROOT / "dist").is_dir():  # release templates (built by scripts/build_release.py)
            template_sources.append(s3deploy.Source.asset(str(ROOT / "dist")))
        s3deploy.BucketDeployment(
            self, "DeployTemplates", sources=template_sources, destination_bucket=templates,
            destination_key_prefix="templates/", prune=False,
        )
        templates_base = f"https://{templates.bucket_name}.s3.{Aws.REGION}.amazonaws.com/templates"

        # ------------------------------------------------------------------ lambdas
        service_code = lambda_.Code.from_asset(str(ROOT / "service"), exclude=["**/__pycache__", "*.pyc"])

        worker_logs = logs.LogGroup(self, "WorkerLogs", retention=logs.RetentionDays.THREE_MONTHS, removal_policy=RemovalPolicy.DESTROY)
        worker_role = iam.Role(
            self, "WorkerRole",
            role_name=WORKER_ROLE_NAME,  # customers' scan roles trust this exact ARN
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Assumes visitors' read-only SecurityStackScanRole (with External ID) to run a scan.",
        )
        worker_logs.grant_write(worker_role)
        worker_role.add_to_policy(iam.PolicyStatement(
            actions=["sts:AssumeRole"],
            resources=["arn:aws:iam::*:role/SecurityStackScanRole-*"],
        ))
        worker = lambda_.Function(
            self, "Worker",
            runtime=RUNTIME, handler="worker.handler", code=service_code,
            timeout=Duration.minutes(10), memory_size=1024, role=worker_role, log_group=worker_logs,
            # Optional cap (-c workerConcurrency=5). Off by default: accounts with the
            # default concurrency quota of 10 can't reserve any.
            reserved_concurrent_executions=int(c) if (c := self.node.try_get_context("workerConcurrency")) else None,
            environment={
                "TABLE_NAME": table.table_name,
                "RESULTS_BUCKET": results.bucket_name,
                "BASELINE_TEMPLATE_URL": f"{templates_base}/securitystack-home.template.json",
            },
            description="SecurityStack: run a read-only scan of a visitor's account",
        )
        table.grant_read_write_data(worker)
        results.grant_put(worker, "results/*")

        api_logs = logs.LogGroup(self, "ApiFunctionLogs", retention=logs.RetentionDays.THREE_MONTHS, removal_policy=RemovalPolicy.DESTROY)
        api_role = iam.Role(self, "ApiRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        api_logs.grant_write(api_role)
        api_fn = lambda_.Function(
            self, "ApiFunction",
            runtime=RUNTIME, handler="api.handler", code=service_code,
            timeout=Duration.seconds(15), memory_size=256, role=api_role, log_group=api_logs,
            environment={
                "TABLE_NAME": table.table_name,
                "RESULTS_BUCKET": results.bucket_name,
                "WORKER_FUNCTION": worker.function_name,
                "SCAN_ROLE_TEMPLATE_URL": f"{templates_base}/scan-role.yaml",
            },
            description="SecurityStack: free-scan API",
        )
        table.grant_read_write_data(api_fn)
        results.grant_read(api_fn, "results/*")
        worker.grant_invoke(api_fn)

        # --------------------------------------------------------------------- API
        http_api = apigw.HttpApi(self, "Api", description="SecurityStack free-scan API", create_default_stage=True)
        integration = integrations.HttpLambdaIntegration("ApiIntegration", api_fn)
        http_api.add_routes(path="/api/scans", methods=[apigw.HttpMethod.POST], integration=integration)
        http_api.add_routes(path="/api/scans/{scanId}/start", methods=[apigw.HttpMethod.POST], integration=integration)
        http_api.add_routes(path="/api/scans/{scanId}", methods=[apigw.HttpMethod.GET], integration=integration)

        stage = http_api.default_stage.node.default_child
        access_log_group = logs.LogGroup(self, "ApiAccessLogs", retention=logs.RetentionDays.THREE_MONTHS, removal_policy=RemovalPolicy.DESTROY)
        stage.default_route_settings = apigw.CfnStage.RouteSettingsProperty(throttling_burst_limit=20, throttling_rate_limit=5)
        stage.access_log_settings = apigw.CfnStage.AccessLogSettingsProperty(
            destination_arn=access_log_group.log_group_arn,
            format='{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","method":"$context.httpMethod",'
                   '"path":"$context.path","status":"$context.status","latency":"$context.responseLatency"}',
        )

        # --------------------------------------------------------- site + CloudFront
        site = s3.Bucket(
            self, "Site",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            server_access_logs_bucket=access_logs,
            server_access_logs_prefix="site/",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        headers = cloudfront.ResponseHeadersPolicy(
            self, "SecurityHeaders",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(content_security_policy=CSP, override=True),
                strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.days(365), include_subdomains=True, override=True),
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(override=True),
                frame_options=cloudfront.ResponseHeadersFrameOptions(frame_option=cloudfront.HeadersFrameOption.DENY, override=True),
                referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                    referrer_policy=cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override=True),
            ),
        )
        api_domain = Fn.select(2, Fn.split("/", http_api.api_endpoint))
        cert = acm.Certificate.from_certificate_arn(self, "Cert", certificate_arn) if certificate_arn else None
        distribution = cloudfront.Distribution(
            self, "Distribution",
            comment="SecurityStack free scan",
            default_root_object="index.html",
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021 if cert else None,
            domain_names=[domain_name] if (domain_name and cert) else None,
            certificate=cert,
            enable_logging=True,
            log_bucket=access_logs,
            log_file_prefix="cloudfront/",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(site),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=headers,
            ),
            additional_behaviors={
                "/api/*": cloudfront.BehaviorOptions(
                    origin=origins.HttpOrigin(api_domain, protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                    response_headers_policy=headers,
                )
            },
        )
        s3deploy.BucketDeployment(
            self, "DeploySite",
            sources=[s3deploy.Source.asset(str(ROOT / "web"))],
            destination_bucket=site,
            distribution=distribution,
            distribution_paths=["/*"],
        )

        CfnOutput(self, "SiteUrl", value=f"https://{domain_name if (domain_name and cert) else distribution.distribution_domain_name}")
        CfnOutput(self, "TemplatesBaseUrl", value=templates_base)
        CfnOutput(self, "WorkerRoleArn", value=worker_role.role_arn)

        self._suppressions(worker_role, api_role, templates, distribution, http_api)

    def _suppressions(self, worker_role, api_role, templates, distribution, http_api):
        NagSuppressions.add_resource_suppressions(worker_role, [
            {"id": "AwsSolutions-IAM5", "reason": "Scan roles live in visitors' accounts (unknown account IDs); the name prefix and per-scan External ID restrict which roles can be assumed. Other wildcards are CDK grants scoped to this stack's table, bucket prefix and log group."},
        ], apply_to_children=True)
        NagSuppressions.add_stack_suppressions(self, [
            {"id": "AwsSolutions-DDB3", "reason": "Scan sessions are deliberately short-lived (24h TTL); backups would keep visitors' data for 35 days."},
        ])
        NagSuppressions.add_resource_suppressions(api_role, [
            {"id": "AwsSolutions-IAM5", "reason": "CDK-generated grants scoped to this stack's table, results/ prefix and worker function versions."},
        ], apply_to_children=True)
        NagSuppressions.add_resource_suppressions(templates, [
            {"id": "AwsSolutions-S2", "reason": "CloudFormation Launch Stack links require templates on S3; public read is limited to templates/* by policy."},
            {"id": "AwsSolutions-S5", "reason": "Public template bucket is not served through CloudFront because CloudFormation requires an S3 URL."},
        ], apply_to_children=True)
        NagSuppressions.add_resource_suppressions(distribution, [
            {"id": "AwsSolutions-CFR1", "reason": "Free scan is offered worldwide; no geo restriction."},
            {"id": "AwsSolutions-CFR2", "reason": "WAF (~$5+/month) deferred until there is traffic; API Gateway throttling plus per-IP limits in the API cap abuse."},
            {"id": "AwsSolutions-CFR4", "reason": "TLSv1.2_2021 is set; the rule also fires when no custom domain is configured (default CloudFront certificate)."},
        ], apply_to_children=True)
        NagSuppressions.add_resource_suppressions(http_api, [
            {"id": "AwsSolutions-APIG4", "reason": "Public, unauthenticated endpoints by design: a scan session is a random 192-bit token and work only happens against roles that trust our worker with a per-scan External ID."},
        ], apply_to_children=True)
        NagSuppressions.add_stack_suppressions(self, [
            {"id": "AwsSolutions-IAM4", "reason": "AWS-managed policies are used only by CDK's own BucketDeployment / auto-delete helper functions.", "appliesTo": [{"regex": "/^Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole$/"}]},
            {"id": "AwsSolutions-IAM5", "reason": "CDK's BucketDeployment and auto-delete helpers need object-level wildcards on the buckets they manage."},
            {"id": "AwsSolutions-L1", "reason": "CDK-managed helper functions (BucketDeployment, auto-delete) pin their own runtimes."},
        ])
