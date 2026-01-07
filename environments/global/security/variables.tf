# environments/global/security/variables.tf

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "default_tags" {
  description = "Default tags for all resources"
  type        = map(string)
  default = {
    ManagedBy  = "terraform"
    Layer      = "global"
    Component  = "security"
  }
}
