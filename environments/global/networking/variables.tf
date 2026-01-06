# environments/global/networking/variables.tf

variable "aws_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "organization_name" {
  description = "Organization name for resource naming"
  type        = string
}

variable "hub_vpc_cidr" {
  description = "CIDR block for hub VPC"
  type        = string
  default     = "10.255.0.0/16"
}

variable "internal_domain" {
  description = "Internal domain name for Route53 private hosted zone"
  type        = string
  default     = "internal.bank.local"
}

variable "enable_network_firewall" {
  description = "Enable AWS Network Firewall for traffic inspection"
  type        = bool
  default     = true
}

variable "enable_dr_peering" {
  description = "Enable VPC peering to disaster recovery region"
  type        = bool
  default     = true
}

variable "dr_region" {
  description = "Disaster recovery region"
  type        = string
  default     = "us-west-2"
}

variable "dr_vpc_id" {
  description = "VPC ID in disaster recovery region for peering"
  type        = string
  default     = ""
}

variable "blocked_domains" {
  description = "List of domains to block at network firewall"
  type        = list(string)
  default = [
    ".malware.com",
    ".phishing.net",
    ".cryptomining.xyz"
  ]
}

variable "default_tags" {
  description = "Default tags for all resources"
  type        = map(string)
  default = {
    ManagedBy   = "terraform"
    Layer       = "global"
    Component   = "networking"
    Compliance  = "pci-dss-nist"
  }
}
