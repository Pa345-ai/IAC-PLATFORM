#!/bin/bash

# Enterprise Landing Zone Setup Script
# Version: 1.0
# Description: Automated menu-driven tool for bootstrap and deployment.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check requirements
check_requirements() {
    echo -e "${YELLOW}Checking requirements...${NC}"
    
    if ! command -v terraform &> /dev/null; then
        echo -e "${RED}Error: Terraform is not installed. Please install Terraform v1.0+.${NC}"
        exit 1
    fi
    
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}Error: AWS CLI is not installed or configured. Please install and run 'aws configure'.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Requirements met!${NC}"
}

# Function for bootstrap
bootstrap() {
    echo -e "${YELLOW}Starting Bootstrap Phase...${NC}"
    cd bootstrap
    terraform init
    terraform apply -auto-approve
    echo -e "${GREEN}Bootstrap complete. Note the S3 bucket name from outputs.${NC}"
    cd ..
}

# Function for dev deploy
deploy_dev() {
    echo -e "${YELLOW}Deploying to Dev Environment...${NC}"
    terraform init
    terraform apply -var-file=environments/dev.tfvars -auto-approve
    echo -e "${GREEN}Dev deployment complete!${NC}"
}

# Function for prod deploy
deploy_prod() {
    echo -e "${YELLOW}Deploying to Prod Environment...${NC}"
    terraform init
    terraform apply -var-file=environments/prod.tfvars -auto-approve
    echo -e "${GREEN}Prod deployment complete!${NC}"
}

# Main menu
main_menu() {
    while true; do
        echo -e "${GREEN}Enterprise Landing Zone Setup Menu${NC}"
        echo "1. Bootstrap (Create S3 Backend)"
        echo "2. Deploy (Dev Environment)"
        echo "3. Deploy (Prod Environment)"
        echo "4. Exit"
        read -p "Select an option [1-4]: " choice
        
        case $choice in
            1) check_requirements; bootstrap ;;
            2) check_requirements; deploy_dev ;;
            3) check_requirements; deploy_prod ;;
            4) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option. Please select 1-4.${NC}" ;;
        esac
    done
}

# Run the menu
main_menu
