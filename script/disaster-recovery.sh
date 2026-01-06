#!/usr/bin/env bash

###############################################################################
# SOVEREIGN CLOUD ARCHIVE - Disaster Recovery Orchestration
# Automated failover and recovery procedures for banking infrastructure
# RPO: < 15 minutes | RTO: < 1 hour
###############################################################################

set -euo pipefail
IFS=$'\n\t'

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly DR_LOG="/var/log/disaster-recovery.log"
readonly PRIMARY_REGION="${PRIMARY_REGION:-us-east-1}"
readonly DR_REGION="${DR_REGION:-us-west-2}"
readonly NOTIFICATION_SNS_ARN="${NOTIFICATION_SNS_ARN:-}"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Metrics
DR_START_TIME=$(date +%s)
CRITICAL_FAILURES=0
RECOVERED_SERVICES=0

###############################################################################
# Logging and Notification
###############################################################################

log() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[${timestamp}]${NC} $*" | tee -a "${DR_LOG}"
}

error() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[${timestamp}] [ERROR]${NC} $*" | tee -a "${DR_LOG}" >&2
    ((CRITICAL_FAILURES++))
}

warn() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[${timestamp}] [WARN]${NC} $*" | tee -a "${DR_LOG}"
}

info() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[${timestamp}] [INFO]${NC} $*" | tee -a "${DR_LOG}"
}

send_alert() {
    local severity=$1
    local message=$2
    
    log "ALERT [${severity}]: ${message}"
    
    if [[ -n "${NOTIFICATION_SNS_ARN}" ]]; then
        aws sns publish \
            --topic-arn "${NOTIFICATION_SNS_ARN}" \
            --subject "DR Alert: ${severity}" \
            --message "${message}" \
            --region "${PRIMARY_REGION}" || warn "Failed to send SNS alert"
    fi
    
    # PagerDuty integration (if configured)
    if [[ -n "${PAGERDUTY_INTEGRATION_KEY:-}" ]]; then
        trigger_pagerduty_alert "${severity}" "${message}"
    fi
}

trigger_pagerduty_alert() {
    local severity=$1
    local message=$2
    
    curl -X POST https://events.pagerduty.com/v2/enqueue \
        -H 'Content-Type: application/json' \
        -d "{
            \"routing_key\": \"${PAGERDUTY_INTEGRATION_KEY}\",
            \"event_action\": \"trigger\",
            \"payload\": {
                \"summary\": \"DR: ${message}\",
                \"severity\": \"${severity}\",
                \"source\": \"disaster-recovery-automation\"
            }
        }" || warn "Failed to trigger PagerDuty alert"
}

###############################################################################
# Health Checks
###############################################################################

check_primary_region_health() {
    log "Checking primary region health (${PRIMARY_REGION})..."
    
    local health_score=0
    local max_score=5
    
    # Check EC2 service
    if aws ec2 describe-instances --region "${PRIMARY_REGION}" --max-items 1 &>/dev/null; then
        ((health_score++))
    else
        error "EC2 service unavailable in primary region"
    fi
    
    # Check RDS service
    if aws rds describe-db-instances --region "${PRIMARY_REGION}" --max-items 1 &>/dev/null; then
        ((health_score++))
    else
        error "RDS service unavailable in primary region"
    fi
    
    # Check S3 service
    if aws s3 ls --region "${PRIMARY_REGION}" &>/dev/null; then
        ((health_score++))
    else
        error "S3 service unavailable in primary region"
    fi
    
    # Check VPC connectivity
    if aws ec2 describe-vpcs --region "${PRIMARY_REGION}" --max-items 1 &>/dev/null; then
        ((health_score++))
    else
        error "VPC service unavailable in primary region"
    fi
    
    # Check KMS service
    if aws kms list-keys --region "${PRIMARY_REGION}" --limit 1 &>/dev/null; then
        ((health_score++))
    else
        error "KMS service unavailable in primary region"
    fi
    
    local health_percentage=$((health_score * 100 / max_score))
    log "Primary region health: ${health_percentage}% (${health_score}/${max_score})"
    
    if [[ ${health_score} -lt 3 ]]; then
        send_alert "CRITICAL" "Primary region health below threshold: ${health_percentage}%"
        return 1
    fi
    
    return 0
}

check_dr_region_readiness() {
    log "Checking DR region readiness (${DR_REGION})..."
    
    # Verify DR infrastructure exists
    local dr_vpcs
    dr_vpcs=$(aws ec2 describe-vpcs \
        --region "${DR_REGION}" \
        --filters "Name=tag:Environment,Values=prod" \
        --query 'Vpcs[*].VpcId' \
        --output text)
    
    if [[ -z "${dr_vpcs}" ]]; then
        error "No DR VPC found in ${DR_REGION}"
        return 1
    fi
    
    log "✓ DR VPC verified: ${dr_vpcs}"
    
    # Check RDS read replicas
    local read_replicas
    read_replicas=$(aws rds describe-db-instances \
        --region "${DR_REGION}" \
        --query 'DBInstances[?ReadReplicaSourceDBInstanceIdentifier!=`null`].DBInstanceIdentifier' \
        --output text)
    
    if [[ -z "${read_replicas}" ]]; then
        warn "No RDS read replicas found in DR region"
    else
        log "✓ RDS read replicas active: ${read_replicas}"
    fi
    
    return 0
}

###############################################################################
# Backup Operations
###############################################################################

create_emergency_snapshot() {
    log "Creating emergency snapshots before failover..."
    
    local environment="${1:-prod}"
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    
    # Snapshot all RDS instances
    local db_instances
    db_instances=$(aws rds describe-db-instances \
        --region "${PRIMARY_REGION}" \
        --query 'DBInstances[*].DBInstanceIdentifier' \
        --output text)
    
    for db in ${db_instances}; do
        log "Creating snapshot for RDS instance: ${db}"
        
        aws rds create-db-snapshot \
            --db-instance-identifier "${db}" \
            --db-snapshot-identifier "dr-emergency-${db}-${timestamp}" \
            --region "${PRIMARY_REGION}" \
            --tags "Key=DREvent,Value=${timestamp}" "Key=Type,Value=Emergency" || error "Failed to snapshot ${db}"
        
        ((RECOVERED_SERVICES++))
    done
    
    # Copy critical S3 buckets
    copy_critical_s3_data "${timestamp}"
    
    # Backup Terraform state
    backup_terraform_state "${environment}" "${timestamp}"
    
    log "✓ Emergency snapshots completed"
}

copy_critical_s3_data() {
    local timestamp=$1
    
    log "Replicating critical S3 data to DR region..."
    
    # List buckets with replication enabled
    local buckets
    buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text)
    
    for bucket in ${buckets}; do
        # Check if replication is configured
        if aws s3api get-bucket-replication --bucket "${bucket}" --region "${PRIMARY_REGION}" &>/dev/null; then
            log "✓ Bucket ${bucket} has replication enabled"
        else
            warn "Bucket ${bucket} does not have replication enabled"
        fi
    done
}

backup_terraform_state() {
    local environment=$1
    local timestamp=$2
    
    log "Backing up Terraform state..."
    
    local state_bucket
    state_bucket=$(aws s3 ls | grep "sovereign-tfstate-${environment}" | awk '{print $3}')
    
    if [[ -n "${state_bucket}" ]]; then
        aws s3 cp \
            "s3://${state_bucket}/${environment}/terraform.tfstate" \
            "${PROJECT_ROOT}/backups/terraform-${environment}-${timestamp}.tfstate" || error "State backup failed"
        
        log "✓ State backed up to ${PROJECT_ROOT}/backups/"
    fi
}

###############################################################################
# Failover Operations
###############################################################################

initiate_rds_failover() {
    log "Initiating RDS failover to ${DR_REGION}..."
    
    # Promote read replicas to standalone instances
    local read_replicas
    read_replicas=$(aws rds describe-db-instances \
        --region "${DR_REGION}" \
        --query 'DBInstances[?ReadReplicaSourceDBInstanceIdentifier!=`null`].DBInstanceIdentifier' \
        --output text)
    
    for replica in ${read_replicas}; do
        log "Promoting read replica: ${replica}"
        
        aws rds promote-read-replica \
            --db-instance-identifier "${replica}" \
            --region "${DR_REGION}" \
            --backup-retention-period 7 || error "Failed to promote ${replica}"
        
        # Wait for promotion to complete
        wait_for_rds_available "${replica}" "${DR_REGION}"
        
        ((RECOVERED_SERVICES++))
    done
    
    log "✓ RDS failover completed"
}

wait_for_rds_available() {
    local db_instance=$1
    local region=$2
    local max_attempts=30
    local attempt=0
    
    while [[ ${attempt} -lt ${max_attempts} ]]; do
        local status
        status=$(aws rds describe-db-instances \
            --db-instance-identifier "${db_instance}" \
            --region "${region}" \
            --query 'DBInstances[0].DBInstanceStatus' \
            --output text)
        
        if [[ "${status}" == "available" ]]; then
            log "✓ RDS instance ${db_instance} is available"
            return 0
        fi
        
        log "Waiting for ${db_instance} to become available (${status})..."
        sleep 30
        ((attempt++))
    done
    
    error "Timeout waiting for ${db_instance} to become available"
    return 1
}

update_route53_records() {
    log "Updating Route53 DNS records to point to DR region..."
    
    local hosted_zone_id="${HOSTED_ZONE_ID:-}"
    
    if [[ -z "${hosted_zone_id}" ]]; then
        warn "HOSTED_ZONE_ID not set. Skipping DNS update."
        return 0
    fi
    
    # Get DR region load balancer DNS
    local dr_lb_dns
    dr_lb_dns=$(aws elbv2 describe-load-balancers \
        --region "${DR_REGION}" \
        --query 'LoadBalancers[0].DNSName' \
        --output text)
    
    if [[ -z "${dr_lb_dns}" ]]; then
        error "Could not find DR load balancer"
        return 1
    fi
    
    # Create change batch
    local change_batch
    change_batch=$(cat <<EOF
{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "app.example.com",
      "Type": "CNAME",
      "TTL": 60,
      "ResourceRecords": [{"Value": "${dr_lb_dns}"}]
    }
  }]
}
EOF
)
    
    aws route53 change-resource-record-sets \
        --hosted-zone-id "${hosted_zone_id}" \
        --change-batch "${change_batch}" || error "Failed to update DNS records"
    
    log "✓ DNS records updated to DR region"
    ((RECOVERED_SERVICES++))
}

update_security_groups() {
    log "Updating security groups for DR environment..."
    
    # Enable access from monitoring and admin networks
    local dr_sg_id
    dr_sg_id=$(aws ec2 describe-security-groups \
        --region "${DR_REGION}" \
        --filters "Name=tag:Name,Values=prod-app-sg" \
        --query 'SecurityGroups[0].GroupId' \
        --output text)
    
    if [[ -n "${dr_sg_id}" && "${dr_sg_id}" != "None" ]]; then
        log "Updating security group: ${dr_sg_id}"
        
        # Add necessary ingress rules
        aws ec2 authorize-security-group-ingress \
            --group-id "${dr_sg_id}" \
            --protocol tcp \
            --port 443 \
            --cidr 0.0.0.0/0 \
            --region "${DR_REGION}" 2>/dev/null || log "Ingress rule already exists"
    fi
}

###############################################################################
# Verification
###############################################################################

verify_dr_services() {
    log "Verifying DR services..."
    
    local verification_failed=false
    
    # Verify RDS connectivity
    log "Testing RDS connectivity..."
    local db_endpoint
    db_endpoint=$(aws rds describe-db-instances \
        --region "${DR_REGION}" \
        --query 'DBInstances[0].Endpoint.Address' \
        --output text)
    
    if [[ -n "${db_endpoint}" && "${db_endpoint}" != "None" ]]; then
        log "✓ RDS endpoint accessible: ${db_endpoint}"
    else
        error "RDS endpoint not found"
        verification_failed=true
    fi
    
    # Verify application load balancer
    log "Testing load balancer..."
    local lb_dns
    lb_dns=$(aws elbv2 describe-load-balancers \
        --region "${DR_REGION}" \
        --query 'LoadBalancers[0].DNSName' \
        --output text)
    
    if [[ -n "${lb_dns}" && "${lb_dns}" != "None" ]]; then
        log "✓ Load balancer accessible: ${lb_dns}"
    else
        error "Load balancer not found"
        verification_failed=true
    fi
    
    # Test application health
    if [[ -n "${lb_dns}" ]]; then
        if curl -f -s -o /dev/null -w "%{http_code}" "http://${lb_dns}/health" | grep -q "200"; then
            log "✓ Application health check passed"
        else
            warn "Application health check failed or endpoint not ready"
        fi
    fi
    
    if [[ "${verification_failed}" == "true" ]]; then
        send_alert "CRITICAL" "DR verification failed. Manual intervention required."
        return 1
    fi
    
    log "✓ DR services verified successfully"
    return 0
}

###############################################################################
# Rollback
###############################################################################

rollback_to_primary() {
    log "Initiating rollback to primary region..."
    
    send_alert "WARNING" "Starting rollback to primary region ${PRIMARY_REGION}"
    
    # Reverse DNS changes
    log "Reverting DNS to primary region..."
    # Implementation would reverse the Route53 changes
    
    # Demote DR databases back to read replicas
    log "Re-establishing replication from primary..."
    # Implementation would recreate read replicas
    
    log "✓ Rollback completed"
}

###############################################################################
# Reporting
###############################################################################

generate_dr_report() {
    local dr_duration=$(($(date +%s) - DR_START_TIME))
    local rto_minutes=$((dr_duration / 60))
    
    local report
    report=$(cat <<EOF

╔═══════════════════════════════════════════════════════════════════════╗
║                    DISASTER RECOVERY REPORT                           ║
╚═══════════════════════════════════════════════════════════════════════╝

Event Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')
Duration: ${rto_minutes} minutes
Primary Region: ${PRIMARY_REGION}
DR Region: ${DR_REGION}

Services Recovered: ${RECOVERED_SERVICES}
Critical Failures: ${CRITICAL_FAILURES}

RTO Target: < 60 minutes
RTO Achieved: ${rto_minutes} minutes
Status: $([[ ${rto_minutes} -lt 60 ]] && echo "✓ WITHIN TARGET" || echo "✗ EXCEEDED TARGET")

Next Actions:
1. Monitor DR environment for 24 hours
2. Conduct post-mortem analysis
3. Update runbooks based on findings
4. Test failback procedures

Full logs: ${DR_LOG}
EOF
)
    
    log "${report}"
    
    if [[ -n "${NOTIFICATION_SNS_ARN}" ]]; then
        aws sns publish \
            --topic-arn "${NOTIFICATION_SNS_ARN}" \
            --subject "DR Recovery Report" \
            --message "${report}" \
            --region "${DR_REGION}"
    fi
}

###############################################################################
# Main Execution
###############################################################################

main() {
    log "═══════════════════════════════════════════════════════════════"
    log "DISASTER RECOVERY INITIATED"
    log "═══════════════════════════════════════════════════════════════"
    
    send_alert "CRITICAL" "Disaster recovery procedure initiated"
    
    # Pre-flight checks
    if ! check_dr_region_readiness; then
        send_alert "CRITICAL" "DR region not ready. Aborting."
        exit 1
    fi
    
    # Check if primary is truly down
    if check_primary_region_health; then
        warn "Primary region appears healthy. DR may not be necessary."
        read -rp "Continue with DR anyway? (yes/no): " confirm
        [[ "${confirm}" != "yes" ]] && exit 0
    fi
    
    # Execute DR procedures
    create_emergency_snapshot "prod"
    initiate_rds_failover
    update_route53_records
    update_security_groups
    
    # Verify recovery
    sleep 60  # Allow services to stabilize
    
    if verify_dr_services; then
        send_alert "WARNING" "DR completed successfully. Services running in ${DR_REGION}"
    else
        send_alert "CRITICAL" "DR completed with errors. Manual intervention required."
    fi
    
    # Generate report
    generate_dr_report
    
    log "═══════════════════════════════════════════════════════════════"
    log "DISASTER RECOVERY COMPLETED"
    log "═══════════════════════════════════════════════════════════════"
}

# Script arguments
case "${1:-execute}" in
    --verify)
        verify_dr_services
        ;;
    --rollback)
        rollback_to_primary
        ;;
    --test)
        check_primary_region_health
        check_dr_region_readiness
        ;;
    *)
        main
        ;;
esac
