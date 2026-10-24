"""Small helpers shared by the SecurityStack constructs."""

from pathlib import Path

from aws_cdk import CfnCondition, CfnParameter, CfnResource, Fn, aws_lambda as lambda_
from constructs import IConstruct

# One place to bump the Lambda runtime (cdk-nag AwsSolutions-L1 requires the latest).
RUNTIME = lambda_.Runtime.PYTHON_3_14

LAMBDA_DIR = Path(__file__).resolve().parents[2] / "lambdas"


def inline_source(name: str) -> str:
    """Return the source of lambdas/<name>/index.py for inline (ZipFile) deployment.

    Inline code keeps the one-click templates free of S3 assets, so a customer can
    launch them without bootstrapping CDK. The same file is imported by the unit tests.
    """
    return (LAMBDA_DIR / name / "index.py").read_text(encoding="utf-8")


def bool_param(scope, id_: str, *, default: bool, description: str) -> CfnParameter:
    param = CfnParameter(
        scope,
        id_,
        type="String",
        allowed_values=["true", "false"],
        default="true" if default else "false",
        description=description,
    )
    # Customers see these names in the CloudFormation console, so keep them clean
    # instead of CDK's path-hashed logical IDs.
    param.override_logical_id(id_)
    return param


def is_true(scope, id_: str, param: CfnParameter) -> CfnCondition:
    cond = CfnCondition(scope, id_, expression=Fn.condition_equals(param.value_as_string, "true"))
    cond.override_logical_id(id_)
    return cond


def apply_condition(condition: CfnCondition, *constructs: IConstruct) -> None:
    """Attach a CloudFormation condition to every L1 resource under the given constructs."""
    for c in constructs:
        for node in c.node.find_all():
            if isinstance(node, CfnResource):
                node.cfn_options.condition = condition
