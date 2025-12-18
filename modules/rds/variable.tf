variable "app_name" {
  description = "Name prefix for resources"
  type        = string
}

variable "db_name" {
  description = "Name of the database"
  type        = string
}

variable "db_username" {
  description = "Database admin username"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for KMS key placement"
  type        = string
}

variable "subnet_ids" {
  description = "List of private subnet IDs for DB subnet group"
  type        = list(string)
}

variable "security_group_id" {
  description = "Security group ID for RDS access"
  type        = string
}
