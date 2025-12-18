variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "App name prefix"
  type        = string
  default     = "enterprise-app"
}

variable "db_name" {
  description = "DB name"
  type        = string
  default     = "webappdb"
}

variable "db_username" {
  description = "DB username"
  type        = string
  default     = "dbadmin"
}

variable "allowed_cidr" {
  description = "Allowed CIDR for ALB"
  type        = string
  default     = "0.0.0.0/0"
}

variable "domain_name" {
  description = "Domain name for SSL and DNS"
  type        = string
  # Example: "myapp.example.com"
}

variable "desired_count" {
  description = "ECS desired count"
  type        = number
  default     = 1
}
