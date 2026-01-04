variable "app_name" { type = string }
variable "vpc_id" { type = string }
variable "allowed_cidr" { type = string }
variable "domain_name" { type = string }
variable "public_subnet_ids" { type = list(string) }
