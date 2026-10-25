#!/usr/bin/env bash
# Remove SecurityStack from an AWS account. Run in AWS CloudShell (it has the AWS CLI
# and Python/boto3). Dry run by default: it lists what it would delete and stops.
#
#   bash teardown.sh                    # dry run: baseline + leftovers (keeps the site)
#   bash teardown.sh --yes              # do it
#   bash teardown.sh --everything       # dry run: also the site, CDK bootstrap, GitHub deploy role
#   bash teardown.sh --everything --yes # do all of it
#
# Only touches resources SecurityStack created: stacks named SecurityStack*/CDKToolkit,
# buckets whose names start with those stacks' prefixes, /securitystack/* parameters,
# and log groups with SecurityStack in the name. Services you had before
# (e.g. your own GuardDuty or Security Hub) are left alone: the baseline stack only
# removes what it turned on.
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
DO=false; ALL=false
for a in "$@"; do
  case "$a" in
    --yes) DO=true ;;
    --everything) ALL=true ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
echo "Account $ACCOUNT, region $REGION. Mode: $($DO && echo DELETE || echo DRY-RUN), scope: $($ALL && echo everything || echo 'baseline + leftovers (site kept)')"
echo

run() { if $DO; then "$@"; else echo "  would run: $*"; fi; }

stacks() {
  aws cloudformation list-stacks --region "$REGION" \
    --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE ROLLBACK_COMPLETE CREATE_FAILED DELETE_FAILED IMPORT_COMPLETE \
    --query "StackSummaries[?starts_with(StackName, '$1')].StackName" --output text
}

delete_stack() {
  local name=$1
  echo "Stack: $name"
  run aws cloudformation delete-stack --region "$REGION" --stack-name "$name"
  if $DO; then
    aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$name" \
      && echo "  deleted" || echo "  !! delete did not finish; check the CloudFormation console"
  fi
}

empty_and_delete_bucket() {
  local b=$1
  echo "Bucket: $b"
  if $DO; then
    python3 - "$b" <<'PY'
import sys, boto3
b = boto3.resource("s3").Bucket(sys.argv[1])
b.object_versions.delete()   # versioned log bucket: delete every version
b.objects.all().delete()
b.delete()
print("  emptied and deleted")
PY
  else
    echo "  would empty (all versions) and delete"
  fi
}

# 1. Scan-role stacks created while testing the free check
for s in $(stacks SecurityStackScanRole); do delete_stack "$s"; done

# 2. The baseline: removes only the services it turned on (Config, Inspector,
#    Access Analyzer, trail...), plus its alerts, digest and roles.
for s in $(stacks SecurityStackHome) $(stacks SecurityStackRegion); do delete_stack "$s"; done

# 3. Things kept on purpose by the baseline (log/report buckets) and by failed test runs.
PREFIXES="securitystackhome-"
$ALL && PREFIXES="$PREFIXES securitystackscanservice- cdk-hnb659fds-assets-$ACCOUNT-"
for p in $PREFIXES; do
  for b in $(aws s3api list-buckets --query "Buckets[?starts_with(Name, '$p')].Name" --output text); do
    empty_and_delete_bucket "$b"
  done
done

for g in $(aws logs describe-log-groups --region "$REGION" --query "logGroups[?contains(logGroupName, 'SecurityStackHome') || contains(logGroupName, 'SecurityStackRegion')].logGroupName" --output text); do
  echo "Log group: $g"; run aws logs delete-log-group --region "$REGION" --log-group-name "$g"
done

for p in $(aws ssm describe-parameters --region "$REGION" --parameter-filters "Key=Name,Option=BeginsWith,Values=/securitystack/" --query "Parameters[].Name" --output text); do
  echo "Parameter: $p"; run aws ssm delete-parameter --region "$REGION" --name "$p"
done

if $ALL; then
  # 4. The hosted site / free check
  for s in $(stacks SecurityStackScanService); do delete_stack "$s"; done
  for g in $(aws logs describe-log-groups --region "$REGION" --query "logGroups[?contains(logGroupName, 'SecurityStackScanService')].logGroupName" --output text); do
    echo "Log group: $g"; run aws logs delete-log-group --region "$REGION" --log-group-name "$g"
  done
  # 5. GitHub deploy role, then the CDK bootstrap stack (its asset bucket was emptied above)
  for s in $(stacks SecurityStackGitHubDeploy) $(stacks github-deploy); do delete_stack "$s"; done
  for s in $(stacks CDKToolkit); do delete_stack "$s"; done
  # 6. The site needed account-level S3 Block Public Access relaxed; turn it fully back on.
  echo "Account-level S3 Block Public Access: turn all four settings back on"
  run aws s3control put-public-access-block --account-id "$ACCOUNT" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
fi

echo
$DO && echo "Done." || echo "Dry run only. Re-run with --yes to delete the items above."
