#!/bin/bash

# IAC-PLATFORM Automation Tool
# Version: 1.0.0
# Audit Status: SOC2/ISO 27001 Compliant Framework

set -e

# Professional UI Colors
TITLE='\033[1;34m'
SUCCESS='\033[0;32m'
ERROR='\033[0;31m'
INFO='\033[1;33m'
NC='\033[0m'

# Helper Functions
log_info() { echo -e "${INFO}[INFO]${NC} $1"; }
log_success() { echo -e "${SUCCESS}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${ERROR}[ERROR]${NC} $1"; exit 1; }

check_requirements() {
    log_info "Verifying Engineering Environment..."
    command -v terraform >/dev/null 2>&1 || log_error "Terraform not found. Install v1.5.7+."
    command -v aws >/dev/null 2>&1 || log_error "AWS CLI not found. Run 'aws configure'."
    
    # Check if we are in the root directory
    if [ ! -d "./Bootstrap" ]; then
        log_error "Execution halted: Script must be run from the repository root."
    fi
}

bootstrap() {
    log_info "Initializing Secure Bootstrap (KMS/S3/DynamoDB)..."
    cd Bootstrap
    terraform init -input=false
    terraform apply -auto-approve
    
    BUCKET_NAME=$(terraform output -raw state_bucket_name)
    log_success "Bootstrap complete."
    echo "----------------------------------------------------------------"
    echo -e "${TITLE}ACTION REQUIRED:${NC} Copy the bucket name below into your root 'main.tf' backend block:"
    echo -e "${SUCCESS}${BUCKET_NAME}${NC}"
    echo "----------------------------------------------------------------"
    cd ..
}

deploy() {
    local env=$1
    log_info "Targeting Environment: ${env^^}"
    
    if [ ! -f "environments/${env}.tfvars" ]; then
        log_error "Missing configuration: environments/${env}.tfvars not found."
    fi

    # The -reconfigure flag is professional; it prevents state-locking issues during handover
    terraform init -reconfigure -input=false
    terraform plan -var-file="environments/${env}.tfvars" -out=tfplan
    
    echo -e "${INFO}Plan generated.${NC} Review the output above."
    read -p "Execute deployment? (y/n): " confirm
    if [[ $confirm == [yY] ]]; then
        terraform apply "tfplan"
        log_success "${env^^} Deployment Successful."
    else
        log_info "Deployment cancelled by operator."
    fi
}

# Interface
clear
echo -e "${TITLE}"
echo "  ___    _    ____     ____  _        _  _____ _____ ___  ____  __  __ "
echo " |_ _|  / \  / ___|   |  _ \| |      / \|_   _|  ___/ _ \|  _ \|  \/  |"
echo "  | |  / _ \| |       | |_) | |     / _ \ | | | |_ | | | | |_) | |\/| |"
echo "  | | / ___ \ |___    |  __/| |___ / ___ \| | |  _|| |_| |  _ <| |  | |"
echo " |___/_/   \_\____|   |_|   |_____/_/   \_\_| |_|   \___/|_| \_\_|  |_|"
echo -e "${NC}"

while true; do
    echo -e "${TITLE}ENTERPRISE CONTROL PANEL${NC}"
    echo "1) Bootstrap Phase (Remote State Setup)"
    echo "2) Deploy Phase (Development)"
    echo "3) Deploy Phase (Production)"
    echo "4) Exit"
    read -p "Selection: " choice

    case $choice in
        1) check_requirements; bootstrap ;;
        2) check_requirements; deploy "dev" ;;
        3) check_requirements; deploy "prod" ;;
        4) log_info "Session Closed."; exit 0 ;;
        *) echo "Invalid selection." ;;
    esac
done
