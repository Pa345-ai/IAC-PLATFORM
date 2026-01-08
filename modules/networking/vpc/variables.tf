# modules/networking/vpc/variables.tf

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  
  validation {
    condition     = can(regex("^(dev|staging|prod|hub)$", var.environment))
    error_message = "Environment must be dev, staging, prod, or hub."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "multi_az" {
  description = "Deploy across multiple availability zones for high availability"
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring"
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Number of days to retain flow logs"
  type        = number
  default     = 90
  
  validation {
    condition     = var.flow_log_retention_days >= 1 && var.flow_log_retention_days <= 3653
    error_message = "Flow log retention must be between 1 and 3653 days."
  }
}

variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints for AWS services"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "ARN of KMS key for log encryption"
  type        = string
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default     = {}
}
