# environments/staging/backend.tf

terraform {
  backend "s3" {
    # Configuration provided via backend.hcl or -backend-config flags
    key = "staging/terraform.tfstate"
  }
}
