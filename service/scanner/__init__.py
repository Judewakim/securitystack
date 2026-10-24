"""SecurityStack read-only AWS account scanner.

Used by the hosted free scan. Every call is a read (List/Describe/Get), so it
runs with nothing more than the AWS-managed SecurityAudit policy.
"""

from .runner import run_scan  # noqa: F401
