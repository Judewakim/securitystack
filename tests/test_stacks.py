"""Infrastructure tests: assert the synthesized templates do what the README promises."""

import json

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Annotations, Match, Template
from cdk_nag import AwsSolutionsChecks

from securitystack.stacks import SecurityStackHome, SecurityStackRegion


@pytest.fixture(scope="module")
def stacks():
    app = cdk.App(context={"release": "true"})
    home = SecurityStackHome(app, "Home", synthesizer=cdk.BootstraplessSynthesizer())
    region = SecurityStackRegion(app, "Region", synthesizer=cdk.BootstraplessSynthesizer())
    cdk.Aspects.of(app).add(AwsSolutionsChecks())
    app.synth()
    return home, region


@pytest.fixture(scope="module")
def home_t(stacks):
    return Template.from_stack(stacks[0])


@pytest.fixture(scope="module")
def region_t(stacks):
    return Template.from_stack(stacks[1])


def test_no_unsuppressed_cdk_nag_errors(stacks):
    for stack in stacks:
        errors = Annotations.from_stack(stack).find_error("*", Match.string_like_regexp("AwsSolutions-.*"))
        assert errors == [], [e.entry.data for e in errors]


def test_customer_facing_parameter_names(home_t, region_t):
    home_params = home_t.to_json()["Parameters"]
    for name in (
        "AlertEmail", "CreateTrail", "LogRetentionDays", "EnableGuardDuty", "EnableSecurityHub",
        "EnableConfigRecorder", "EnableAccessAnalyzer", "EnableInspector",
        "AutoFixEbsDefaultEncryption", "AutoFixS3AccountBlockPublicAccess",
    ):
        assert name in home_params, name
    assert "ConfigBucketName" in region_t.to_json()["Parameters"]
    assert "BootstrapVersion" not in home_params


def test_auto_fixes_are_off_by_default(home_t):
    params = home_t.to_json()["Parameters"]
    assert params["AutoFixEbsDefaultEncryption"]["Default"] == "false"
    assert params["AutoFixS3AccountBlockPublicAccess"]["Default"] == "false"


def test_buckets_are_private_and_tls_only(home_t):
    buckets = home_t.find_resources("AWS::S3::Bucket")
    assert len(buckets) == 3
    for b in buckets.values():
        pab = b["Properties"]["PublicAccessBlockConfiguration"]
        assert all(pab[k] for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"))
        assert b["DeletionPolicy"] == "Retain"
    policies = json.dumps(home_t.find_resources("AWS::S3::BucketPolicy"))
    assert '"aws:SecureTransport": "false"' in policies


def test_log_bucket_policy_is_scoped_to_this_account(home_t):
    policies = json.dumps(home_t.find_resources("AWS::S3::BucketPolicy"))
    assert "aws:SourceAccount" in policies
    assert "aws:SourceArn" in policies


def test_config_role_can_write_to_log_bucket(home_t, region_t):
    for t in (home_t, region_t):
        pols = json.dumps(t.find_resources("AWS::IAM::Policy"))
        assert "SecurityStackConfigDelivery" in pols and "s3:PutObject" in pols


def test_log_retention_minimum_is_past_glacier_transition(home_t):
    assert home_t.to_json()["Parameters"]["LogRetentionDays"]["MinValue"] > 90


def test_alerts_go_through_dedupe_lambda(home_t):
    rules = [r for r in home_t.find_resources("AWS::Events::Rule").values() if r["Properties"].get("EventPattern")]
    for r in rules:
        assert "Fn::GetAtt" in json.dumps(r["Properties"]["Targets"][0]["Arn"])  # a Lambda, not SNS directly
    pols = json.dumps(home_t.find_resources("AWS::IAM::Policy"))
    assert "securityhub:BatchUpdateFindings" in pols


def test_alerts_only_for_new_active_high_or_critical(home_t):
    rules = home_t.find_resources("AWS::Events::Rule")
    patterns = [r["Properties"].get("EventPattern") for r in rules.values() if r["Properties"].get("EventPattern")]
    assert len(patterns) == 2
    for p in patterns:
        f = p["detail"]["findings"]
        assert f["Severity"]["Label"] == ["HIGH", "CRITICAL"]
        assert f["Workflow"]["Status"] == ["NEW"]
        assert f["RecordState"] == ["ACTIVE"]


def test_weekly_digest_schedule(home_t):
    home_t.has_resource_properties("AWS::Events::Rule", {"ScheduleExpression": "cron(0 13 ? * MON *)"})


def test_no_s3_assets_so_one_click_works(stacks):
    for stack in stacks:
        t = json.dumps(Template.from_stack(stack).to_json())
        assert "AssetParameters" not in t
        assert "cdk-hnb659fds-assets" not in t
        for fn in Template.from_stack(stack).find_resources("AWS::Lambda::Function").values():
            assert "ZipFile" in fn["Properties"]["Code"]


def test_lambda_roles_have_no_admin_wildcards(home_t):
    for pol in home_t.find_resources("AWS::IAM::Policy").values():
        for stmt in pol["Properties"]["PolicyDocument"]["Statement"]:
            actions = stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]]
            assert "*" not in actions
            assert not any(a.endswith(":*") for a in actions if isinstance(a, str) and not a.startswith("s3:"))


def _baseline_props(t):
    res = [r for r in t.find_resources("AWS::CloudFormation::CustomResource").values()
           if "LogBucketName" in r["Properties"]]
    assert len(res) == 1
    return res[0]["Properties"]


def test_no_native_service_resources_that_fail_on_existing_services(home_t, region_t):
    """One click must work on accounts that already run these services."""
    for t in (home_t, region_t):
        for rtype in ("AWS::GuardDuty::Detector", "AWS::SecurityHub::Hub", "AWS::SecurityHub::Standard",
                      "AWS::Config::ConfigurationRecorder", "AWS::AccessAnalyzer::Analyzer",
                      "AWS::CloudTrail::Trail", "AWS::SecurityHub::FindingAggregator"):
            assert t.find_resources(rtype) == {}, rtype


def test_baseline_function_gets_every_switch(home_t, region_t):
    home = _baseline_props(home_t)
    for key in ("EnableGuardDuty", "EnableSecurityHub", "EnableConfigRecorder", "EnableAccessAnalyzer",
                "EnableInspector", "CreateTrail", "AutoFixS3AccountBlockPublicAccess", "AutoFixEbsDefaultEncryption"):
        assert key in home, key
    assert home["IsHomeRegion"] == "true"
    region = _baseline_props(region_t)
    assert region["IsHomeRegion"] == "false" and "CreateTrail" not in region


def test_baseline_runs_after_bucket_policy_and_roles(home_t):
    res = next(k for k, r in home_t.find_resources("AWS::CloudFormation::CustomResource").items()
               if "LogBucketName" in r["Properties"])
    deps = home_t.to_json()["Resources"][res]["DependsOn"]
    assert any("LogBucketPolicy" in d for d in deps)
    assert any("ConfigDeliveryPolicy" in d for d in deps)


def test_baseline_role_can_create_service_linked_roles(home_t):
    """The Inspector deploy failed without the agentless service-linked role."""
    pols = json.dumps(home_t.find_resources("AWS::IAM::Policy"))
    for svc in ("inspector2.amazonaws.com", "agentless.inspector2.amazonaws.com", "guardduty.amazonaws.com",
                "securityhub.amazonaws.com", "access-analyzer.amazonaws.com"):
        assert svc in pols, svc
    assert '"iam:PassedToService": "config.amazonaws.com"' in pols
