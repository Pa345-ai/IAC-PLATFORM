# environments/staging/providers.tf

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = "staging"
      ManagedBy   = "terraform"
      Repository  = "sovereign-cloud-archive"
      CostCenter  = "staging"
    }
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "tfstate_bucket" {
  description = "S3 bucket for Terraform state"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for staging VPC"
  type        = string
  default     = "10.1.0.0/16"
}
