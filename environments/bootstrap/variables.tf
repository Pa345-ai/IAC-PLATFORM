variable "aws_region" {
  description = "AWS region for bootstrap resources"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition     = can(regex("^(us|eu|ap|sa|ca|me|af)-(north|south|east|west|central|northeast|southeast|southwest)-[1-3]$", var.aws_region))
    error_message = "Must be a valid AWS region."
  }
}

variable "environment" {
  description = "Environment name (bootstrap for state backend)"
  type        = string
  default     = "bootstrap"
  
  validation {
    condition     = can(regex("^(bootstrap|dev|staging|prod)$", var.environment))
    error_message = "Environment must be bootstrap, dev, staging, or prod."
  }
}

variable "state_bucket_force_destroy" {
  description = "Allow destruction of non-empty state bucket (DANGEROUS)"
  type        = bool
  default     = false
}

variable "enable_versioning" {
  description = "Enable versioning on state bucket"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable access logging for state bucket"
  type        = bool
  default     = true
}

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery for DynamoDB"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain logs before transitioning to Glacier"
  type        = number
  default     = 90
  
  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 365
    error_message = "Log retention must be between 30 and 365 days."
  }
}

variable "kms_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 30
  
  validation {
    condition     = var.kms_deletion_window >= 7 && var.kms_deletion_window <= 30
    error_message = "KMS deletion window must be between 7 and 30 days."
  }
}

variable "enable_key_rotation" {
  description = "Enable automatic KMS key rotation"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
