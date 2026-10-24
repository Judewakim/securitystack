# Security Policy

## Reporting a vulnerability

Email **judewakim@wakimworks.com** with the subject `SECURITY: securitystack`. Please do not open a public issue for security problems.

You'll get an acknowledgement within 3 business days. Please include steps to reproduce and the affected version or commit.

## Design commitments

- **Read-only by default.** The free scan uses a role limited to the AWS-managed `SecurityAudit` policy. It cannot change anything in your account.
- **No long-lived keys.** The scan service never asks for or accepts access keys. It assumes a role you create, protected by a per-scan External ID.
- **No silent changes.** The baseline never modifies existing resources unless you explicitly turn on an auto-fix parameter (all are `false` by default).
- **Short retention.** Scan results are deleted automatically after 24 hours.
