import importlib.util
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Some modules create boto3 clients at import time (as Lambda code should), so
# give them a fake region/credentials before any test module is imported.
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch):
    """Make sure no test can ever touch a real AWS account."""
    for k in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")


def load_lambda(name: str):
    """Import lambdas/<name>/index.py as a uniquely named module."""
    path = ROOT / "lambdas" / name / "index.py"
    spec = importlib.util.spec_from_file_location(f"lambda_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeContext:
    log_stream_name = "test-stream"
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
