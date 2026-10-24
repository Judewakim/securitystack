# Security Policy

## Reporting a vulnerability

Email **judewakim@wakimworks.com** with the subject `SECURITY: securitystack`. Please do not open a public issue for security problems.

You'll get an acknowledgement within 3 business days. Please include steps to reproduce and the affected version or commit.

## Design commitments

- **Read-only, least privilege.** The free scan's role allows only the 26 read calls the scanner makes (see `templates/scan-role.yaml`). It cannot change anything, and unlike AWS's broader `SecurityAudit` policy it cannot read Lambda environment variables or EC2 user data.
- **No long-lived keys.** The scan service never asks for or accepts access keys. It assumes a role you create, which trusts one fixed scanner role and only with a per-scan External ID.
- **No silent changes.** The baseline never modifies existing resources unless you explicitly turn on an auto-fix parameter (all are `false` by default).
- **Short retention.** Scan results are deleted automatically within about 48 hours, with no backups. Operational logs are kept for 90 days.
