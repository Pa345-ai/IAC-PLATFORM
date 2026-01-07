# environments/prod/backend.tf
# Production Backend Configuration - Points to Bootstrap State

terraform {
  backend "s3" {
    # Backend configuration should be provided via:
    # terraform init -backend-config="backend.hcl"
    # OR via -backend-config flags
    # OR via terraform.tfvars
    
    # Example configuration (do not hardcode):
    # bucket         = "sovereign-tfstate-bootstrap-123456789012"
    # key            = "prod/terraform.tfstate"
    # region         = "us-east-1"
    # dynamodb_table = "terraform-state-lock-bootstrap"
    # encrypt        = true
    # kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/..."
  }
}
