#!/usr/bin/env bash

###############################################################################
# SOVEREIGN CLOUD ARCHIVE - Automated Credential Rotation
# Rotates credentials for maximum security (PCI-DSS 8.2.4)
# Frequency: Quarterly or on-demand
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly LOG_FILE="/var/log/credential-rotation.log"
readonly ROTATION_RECORD="${PROJECT_ROOT}/.credential-rotation-history"
readonly AWS_REGION="${AWS_REGION:-us-east-1}"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Counters
ROTATED_COUNT=0
FAILED_COUNT=0

###############################################################################
# Logging Functions
###############################################################################

log() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[${timestamp}]${NC} $*" | tee -a "${LOG_FILE}"
}

error() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[${timestamp}] [ERROR]${NC} $*" | tee -a "${LOG_FILE}" >&2
    ((FAILED_COUNT++))
}

warn() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[${timestamp}] [WARN]${NC} $*" | tee -a "${LOG_FILE}"
}

info() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[${timestamp}] [INFO]${NC} $*" | tee -a "${LOG_FILE}"
}

record_rotation() {
    local credential_type=$1
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "${timestamp}|${credential_type}|SUCCESS" >> "${ROTATION_RECORD}"
}

###############################################################################
# KMS Key Rotation
###############################################################################

rotate_kms_keys() {
    log "Rotating KMS keys..."
    
    # Get all customer-managed KMS keys
    local keys
    keys=$(aws kms list-keys --region "${AWS_REGION}" --query 'Keys[*].KeyId' --output text)
    
    for key_id in ${keys}; do
        # Check if it's a customer-managed key
        local key_metadata
        key_metadata=$(aws kms describe-key --key-id "${key_id}" --region "${AWS_REGION}" 2>/dev/null || echo "")
        
        if [[ -z "${key_metadata}" ]]; then
            continue
        fi
        
        local key_manager
        key_manager=$(echo "${key_metadata}" | jq -r '.KeyMetadata.KeyManager')
        
        if [[ "${key_manager}" == "CUSTOMER" ]]; then
            local alias
            alias=$(aws kms list-aliases --key-id "${key_id}" --region "${AWS_REGION}" --query 'Aliases[0].AliasName' --output text 2>/dev/null || echo "no-alias")
            
            log "Checking rotation status for key: ${key_id} (${alias})"
            
            # Check if rotation is enabled
            local rotation_enabled
            rotation_enabled=$(aws kms get-key-rotation-status --key-id "${key_id}" --region "${AWS_REGION}" --query 'KeyRotationEnabled' --output text)
            
            if [[ "${rotation_enabled}" != "True" ]]; then
                warn "Key ${key_id} does not have automatic rotation enabled. Enabling now..."
                
                aws kms enable-key-rotation --key-id "${key_id}" --region "${AWS_REGION}"
                log "✓ Enabled automatic rotation for ${key_id}"
                ((ROTATED_COUNT++))
            else
                log "✓ Key ${key_id} already has automatic rotation enabled"
            fi
            
            record_rotation "KMS_${key_id}"
        fi
    done
    
    log "✓ KMS key rotation check completed"
}

###############################################################################
# RDS Password Rotation
###############################################################################

rotate_rds_passwords() {
    log "Rotating RDS master passwords..."
    
    # Get all RDS instances
    local instances
    instances=$(aws rds describe-db-instances --region "${AWS_REGION}" --query 'DBInstances[*].DBInstanceIdentifier' --output text)
    
    for instance in ${instances}; do
        log "Rotating password for RDS instance: ${instance}"
        
        # Generate new password (32 chars, high entropy)
        local new_password
        new_password=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 32)
        
        # Modify master password
        if aws rds modify-db-instance \
            --db-instance-identifier "${instance}" \
            --master-user-password "${new_password}" \
            --apply-immediately \
            --region "${AWS_REGION}" &>/dev/null; then
            
            # Store new password in Secrets Manager
            local secret_name="rds/${instance}/master-password"
            
            if aws secretsmanager describe-secret --secret-id "${secret_name}" --region "${AWS_REGION}" &>/dev/null; then
                aws secretsmanager update-secret \
                    --secret-id "${secret_name}" \
                    --secret-string "${new_password}" \
                    --region "${AWS_REGION}"
            else
                aws secretsmanager create-secret \
                    --name "${secret_name}" \
                    --description "Master password for RDS instance ${instance}" \
                    --secret-string "${new_password}" \
                    --region "${AWS_REGION}"
            fi
            
            log "✓ Password rotated for ${instance} and stored in Secrets Manager"
            ((ROTATED_COUNT++))
            record_rotation "RDS_${instance}"
        else
            error "Failed to rotate password for ${instance}"
        fi
    done
    
    log "✓ RDS password rotation completed"
}

###############################################################################
# IAM Access Key Rotation
###############################################################################

rotate_iam_access_keys() {
    log "Rotating IAM access keys..."
    
    # Get all IAM users
    local users
    users=$(aws iam list-users --query 'Users[*].UserName' --output text)
    
    for user in ${users}; do
        log "Checking access keys for user: ${user}"
        
        # Get access keys for user
        local keys
        keys=$(aws iam list-access-keys --user-name "${user}" --query 'AccessKeyMetadata[*].[AccessKeyId,CreateDate]' --output text)
        
        while IFS=$'\t' read -r key_id create_date; do
            # Calculate key age in days
            local create_epoch
            create_epoch=$(date -d "${create_date}" +%s)
            local now_epoch
            now_epoch=$(date +%s)
            local age_days=$(( (now_epoch - create_epoch) / 86400 ))
            
            if [[ ${age_days} -gt 90 ]]; then
                warn "Access key ${key_id} for user ${user} is ${age_days} days old (>90 days)"
                
                # Only rotate if user has only one key
                local key_count
                key_count=$(echo "${keys}" | wc -l)
                
                if [[ ${key_count} -eq 1 ]]; then
                    log "Creating new access key for ${user}..."
                    
                    # Create new key
                    local new_key_output
                    new_key_output=$(aws iam create-access-key --user-name "${user}" --output json)
                    
                    local new_key_id
                    new_key_id=$(echo "${new_key_output}" | jq -r '.AccessKey.AccessKeyId')
                    
                    local new_secret_key
                    new_secret_key=$(echo "${new_key_output}" | jq -r '.AccessKey.SecretAccessKey')
                    
                    # Store in Secrets Manager
                    local secret_name="iam/${user}/access-key"
                    
                    local secret_value
                    secret_value=$(jq -n \
                        --arg aki "${new_key_id}" \
                        --arg sak "${new_secret_key}" \
                        '{AccessKeyId: $aki, SecretAccessKey: $sak}')
                    
                    if aws secretsmanager describe-secret --secret-id "${secret_name}" &>/dev/null; then
                        aws secretsmanager update-secret \
                            --secret-id "${secret_name}" \
                            --secret-string "${secret_value}"
                    else
                        aws secretsmanager create-secret \
                            --name "${secret_name}" \
                            --description "Access key for IAM user ${user}" \
                            --secret-string "${secret_value}"
                    fi
                    
                    log "✓ New access key created for ${user}: ${new_key_id}"
                    log "⚠️  Old key ${key_id} should be deactivated after validating new key"
                    
                    # Optionally deactivate old key after grace period
                    # aws iam update-access-key --user-name "${user}" --access-key-id "${key_id}" --status Inactive
                    
                    ((ROTATED_COUNT++))
                    record_rotation "IAM_${user}"
                else
                    warn "User ${user} has multiple keys. Manual rotation recommended."
                fi
            else
                log "✓ Access key ${key_id} for ${user} is ${age_days} days old (OK)"
            fi
        done <<< "${keys}"
    done
    
    log "✓ IAM access key rotation completed"
}

###############################################################################
# EC2 Key Pair Rotation
###############################################################################

rotate_ec2_key_pairs() {
    log "Auditing EC2 key pairs..."
    
    # List all key pairs
    local key_pairs
    key_pairs=$(aws ec2 describe-key-pairs --region "${AWS_REGION}" --query 'KeyPairs[*].KeyName' --output text)
    
    for key_pair in ${key_pairs}; do
        log "Key pair found: ${key_pair}"
        
        # Get instances using this key
        local instances
        instances=$(aws ec2 describe-instances \
            --region "${AWS_REGION}" \
            --filters "Name=key-name,Values=${key_pair}" "Name=instance-state-name,Values=running" \
            --query 'Reservations[*].Instances[*].InstanceId' \
            --output text)
        
        if [[ -n "${instances}" ]]; then
            warn "Key pair ${key_pair} is in use by instances: ${instances}"
            warn "Manual key rotation required for EC2 instances"
        else
            log "✓ Key pair ${key_pair} not in use"
        fi
    done
    
    log "✓ EC2 key pair audit completed"
}

###############################################################################
# Secrets Manager Rotation
###############################################################################

rotate_secrets_manager() {
    log "Triggering Secrets Manager rotations..."
    
    # Get all secrets
    local secrets
    secrets=$(aws secretsmanager list-secrets --region "${AWS_REGION}" --query 'SecretList[*].Name' --output text)
    
    for secret in ${secrets}; do
        # Check if rotation is configured
        local rotation_config
        rotation_config=$(aws secretsmanager describe-secret --secret-id "${secret}" --region "${AWS_REGION}" --query 'RotationEnabled' --output text 2>/dev/null || echo "false")
        
        if [[ "${rotation_config}" == "true" ]]; then
            log "Rotating secret: ${secret}"
            
            if aws secretsmanager rotate-secret --secret-id "${secret}" --region "${AWS_REGION}" &>/dev/null; then
                log "✓ Rotation triggered for ${secret}"
                ((ROTATED_COUNT++))
                record_rotation "SECRET_${secret}"
            else
                error "Failed to rotate secret ${secret}"
            fi
        else
            warn "Secret ${secret} does not have automatic rotation configured"
        fi
    done
    
    log "✓ Secrets Manager rotation completed"
}

###############################################################################
# Certificate Rotation Check
###############################################################################

check_certificate_expiry() {
    log "Checking SSL/TLS certificate expiry..."
    
    # Get all ACM certificates
    local certificates
    certificates=$(aws acm list-certificates --region "${AWS_REGION}" --query 'CertificateSummaryList[*].CertificateArn' --output text)
    
    for cert_arn in ${certificates}; do
        local cert_details
        cert_details=$(aws acm describe-certificate --certificate-arn "${cert_arn}" --region "${AWS_REGION}" --output json)
        
        local domain
        domain=$(echo "${cert_details}" | jq -r '.Certificate.DomainName')
        
        local not_after
        not_after=$(echo "${cert_details}" | jq -r '.Certificate.NotAfter')
        
        local expiry_epoch
        expiry_epoch=$(date -d "${not_after}" +%s)
        
        local now_epoch
        now_epoch=$(date +%s)
        
        local days_until_expiry=$(( (expiry_epoch - now_epoch) / 86400 ))
        
        if [[ ${days_until_expiry} -lt 30 ]]; then
            error "Certificate for ${domain} expires in ${days_until_expiry} days!"
        elif [[ ${days_until_expiry} -lt 60 ]]; then
            warn "Certificate for ${domain} expires in ${days_until_expiry} days"
        else
            log "✓ Certificate for ${domain} expires in ${days_until_expiry} days (OK)"
        fi
    done
    
    log "✓ Certificate expiry check completed"
}

###############################################################################
# SSH Host Key Rotation
###############################################################################

rotate_ssh_host_keys() {
    log "SSH host key rotation requires manual intervention"
    log "Recommended procedure:"
    log "  1. Generate new host keys on each instance"
    log "  2. Update known_hosts files"
    log "  3. Restart SSH service"
    
    warn "SSH host key rotation not automated - requires manual process"
}

###############################################################################
# Generate Rotation Report
###############################################################################

generate_report() {
    local report_file="${PROJECT_ROOT}/credential-rotation-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "${report_file}" << EOF
╔═══════════════════════════════════════════════════════════════════════╗
║              CREDENTIAL ROTATION REPORT                               ║
╚═══════════════════════════════════════════════════════════════════════╝

Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')
Region: ${AWS_REGION}

Summary:
--------
Total Rotations: ${ROTATED_COUNT}
Failed Rotations: ${FAILED_COUNT}

Status: $([[ ${FAILED_COUNT} -eq 0 ]] && echo "✓ SUCCESS" || echo "✗ PARTIAL FAILURE")

Rotated Credentials:
$(tail -20 "${ROTATION_RECORD}")

Next Rotation Due: $(date -d '+90 days' '+%Y-%m-%d')

Recommendations:
----------------
1. Verify all applications are using new credentials
2. Deactivate old credentials after grace period (7 days)
3. Update credential rotation schedule if needed
4. Review failed rotations and remediate

For support: infrastructure-team@yourbank.com

EOF
    
    log "Report generated: ${report_file}"
    
    # Send report via SNS if configured
    if [[ -n "${NOTIFICATION_SNS_ARN:-}" ]]; then
        aws sns publish \
            --topic-arn "${NOTIFICATION_SNS_ARN}" \
            --subject "Credential Rotation Report" \
            --message file://"${report_file}" \
            --region "${AWS_REGION}"
    fi
}

###############################################################################
# Main Execution
###############################################################################

main() {
    log "═══════════════════════════════════════════════════════════════"
    log "CREDENTIAL ROTATION INITIATED"
    log "═══════════════════════════════════════════════════════════════"
    
    # Pre-flight checks
    if ! aws sts get-caller-identity &>/dev/null; then
        error "AWS credentials not configured"
        exit 1
    fi
    
    # Confirm execution
    if [[ "${SKIP_CONFIRMATION:-false}" != "true" ]]; then
        warn "This will rotate credentials across the infrastructure"
        read -rp "Continue? (yes/no): " confirm
        [[ "${confirm}" != "yes" ]] && exit 0
    fi
    
    # Execute rotations
    rotate_kms_keys
    rotate_rds_passwords
    rotate_iam_access_keys
    rotate_ec2_key_pairs
    rotate_secrets_manager
    check_certificate_expiry
    rotate_ssh_host_keys
    
    # Generate report
    generate_report
    
    log "═══════════════════════════════════════════════════════════════"
    log "CREDENTIAL ROTATION COMPLETED"
    log "Rotated: ${ROTATED_COUNT} | Failed: ${FAILED_COUNT}"
    log "═══════════════════════════════════════════════════════════════"
    
    [[ ${FAILED_COUNT} -gt 0 ]] && exit 1 || exit 0
}

# Handle script arguments
case "${1:-rotate}" in
    --kms-only)
        rotate_kms_keys
        ;;
    --rds-only)
        rotate_rds_passwords
        ;;
    --iam-only)
        rotate_iam_access_keys
        ;;
    --check-only)
        check_certificate_expiry
        ;;
    *)
        main
        ;;
esac
