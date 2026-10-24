# Deploying SecurityStack

There are two separate things to deploy:

| What | Where | Who |
|---|---|---|
| **The baseline** (`SecurityStackHome`, `SecurityStackRegion`) | Any AWS account you want protected | Customers, or you for your own accounts |
| **The free-scan service** (`SecurityStackScanService`) | One vendor account (yours) | Only the operator of the hosted scan |

## The baseline

### Option A: Launch Stack (no tools needed)

1. Open the home template in the region you use most. The free scan builds this link for you with the right switches set; otherwise use the template from the latest GitHub release.
2. Enter an email for alerts, review the switches, tick the IAM acknowledgement and create the stack.
3. **Confirm the subscription email** AWS sends, or you won't get alerts.
4. For each extra region, launch `securitystack-region.template.json` there and paste the home stack's `LogBucketName` output into `ConfigBucketName`.

### Option B: CDK

```bash
pip install -r requirements.txt
npx cdk bootstrap                                  # once per account/region
npx cdk deploy SecurityStackHome -c homeRegion=us-east-1 \
  --parameters AlertEmail=you@example.com
npx cdk deploy SecurityStackRegion-us-west-2 -c regions=us-west-2 \
  --parameters SecurityStackRegion-us-west-2:ConfigBucketName=<LogBucketName output>
```

### If a service is already on

CloudFormation can't take over an existing GuardDuty detector, Security Hub, Config recorder or Access Analyzer; creating a second one fails. Set that service's `Enable…` parameter to `false`. The free scan does this for you in the link it gives you.

### Removing it

Delete the region stacks, then the home stack. Detection services, rules, alerts and the digest are removed. The **log and report buckets are kept on purpose** (they're audit evidence); empty and delete them yourself if you don't need them. Inspector is only turned off if SecurityStack was the one that turned it on. Opt-in auto-fixes (EBS default encryption, S3 Block Public Access) stay on, since turning them off would weaken the account.

## The free-scan service (operator only)

### One-time setup in your staging account

1. **Bootstrap CDK** from CloudShell in the target region: `npx cdk bootstrap`.
2. **Allow one public bucket.** CloudFormation "Launch Stack" links must point at S3, so the service creates one bucket whose `templates/` objects are public-read (nothing else is ever stored there). If the account has account-level S3 Block Public Access on, that bucket's policy will be rejected. Either turn off the account-level *BlockPublicPolicy* / *RestrictPublicBuckets* settings in this vendor account only, or host the service in a dedicated account. Don't do this in an account that stores real data.
3. **Create the GitHub deploy role**: launch [`infra/github-deploy-role.yaml`](../infra/github-deploy-role.yaml) in the same account. It trusts only this repository's `staging` environment and can only assume the CDK bootstrap roles, so no AWS keys are stored in GitHub.
4. In GitHub, go to **Settings > Environments > New environment**, name it `staging`, add yourself as a required reviewer, and add these variables:
   - `AWS_DEPLOY_ROLE_ARN`: the `DeployRoleArn` output from step 3
   - `AWS_REGION`: e.g. `us-east-1`
   - `ALERT_EMAIL`: where staging alerts go
   - optional `DOMAIN_NAME` and `CERTIFICATE_ARN` (an ACM certificate in us-east-1) for a custom domain

### Deploying

Run **Actions > Deploy to staging > Run workflow**. It runs the tests, builds the release templates, deploys the scan service and (optionally) the baseline into the same account. The `SiteUrl` output is the web app.

### Running the web app locally

```bash
python3 scripts/dev_server.py   # http://localhost:8000, with a fake API
```
