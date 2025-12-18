variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Unique S3 bucket name for Terraform state"
  type        = string
  default     = "my-enterprise-terraform-state-12345"  # Change to unique name
}

variable "lock_table_name" {
  description = "DynamoDB table name for locks"
  type        = string
  default     = "terraform-locks"
}
