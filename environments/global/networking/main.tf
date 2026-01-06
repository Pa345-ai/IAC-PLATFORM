# environments/global/networking/main.tf
# Transit Gateway and Global Network Hub

terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    # Backend config provided via -backend-config
    key = "global/networking/terraform.tfstate"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = var.default_tags
  }
}

# Hub VPC for Shared Services
module "hub_vpc" {
  source = "../../../modules/networking/vpc"
  
  environment           = "hub"
  vpc_cidr              = var.hub_vpc_cidr
  multi_az              = true
  enable_flow_logs      = true
  enable_vpc_endpoints  = true
  flow_log_retention_days = 365
  kms_key_arn          = aws_kms_key.networking.arn
  
  tags = {
    Purpose = "SharedServices"
    Type    = "Hub"
  }
}

# Transit Gateway for Inter-VPC Routing
resource "aws_ec2_transit_gateway" "main" {
  description                     = "Bank Transit Gateway for ${var.organization_name}"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support               = "enable"
  auto_accept_shared_attachments = "disable"
  
  tags = {
    Name = "${var.organization_name}-tgw"
  }
}

# Transit Gateway Route Tables
resource "aws_ec2_transit_gateway_route_table" "shared_services" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  
  tags = {
    Name = "shared-services-rt"
    Type = "SharedServices"
  }
}

resource "aws_ec2_transit_gateway_route_table" "production" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  
  tags = {
    Name = "production-rt"
    Type = "Production"
  }
}

resource "aws_ec2_transit_gateway_route_table" "non_production" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  
  tags = {
    Name = "non-production-rt"
    Type = "NonProduction"
  }
}

# Hub VPC Attachment
resource "aws_ec2_transit_gateway_vpc_attachment" "hub" {
  subnet_ids         = module.hub_vpc.private_subnet_ids
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = module.hub_vpc.vpc_id
  
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
  
  dns_support  = "enable"
  ipv6_support = "disable"
  
  tags = {
    Name = "hub-vpc-attachment"
  }
}

# Associate Hub with Shared Services Route Table
resource "aws_ec2_transit_gateway_route_table_association" "hub" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.hub.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.shared_services.id
}

# KMS Key for Network Encryption
resource "aws_kms_key" "networking" {
  description             = "KMS key for network-related encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name    = "networking-kms-key"
    Purpose = "NetworkEncryption"
  }
}

resource "aws_kms_alias" "networking" {
  name          = "alias/networking"
  target_key_id = aws_kms_key.networking.key_id
}

# VPC Peering for DR Region (if enabled)
resource "aws_vpc_peering_connection" "dr_region" {
  count = var.enable_dr_peering ? 1 : 0
  
  vpc_id        = module.hub_vpc.vpc_id
  peer_vpc_id   = var.dr_vpc_id
  peer_region   = var.dr_region
  auto_accept   = false
  
  tags = {
    Name = "hub-to-dr-peering"
    Side = "Requester"
  }
}

# Network Firewall for Traffic Inspection (Optional)
resource "aws_networkfirewall_firewall_policy" "main" {
  count = var.enable_network_firewall ? 1 : 0
  
  name = "${var.organization_name}-firewall-policy"
  
  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    
    stateless_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.drop_remote[0].arn
    }
    
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.block_domains[0].arn
    }
  }
  
  tags = {
    Name = "main-firewall-policy"
  }
}

resource "aws_networkfirewall_rule_group" "drop_remote" {
  count = var.enable_network_firewall ? 1 : 0
  
  capacity = 2
  name     = "drop-remote-ssh-rdp"
  type     = "STATELESS"
  
  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:drop"]
            match_attributes {
              source {
                address_definition = "0.0.0.0/0"
              }
              destination_port {
                from_port = 22
                to_port   = 22
              }
              protocols = [6]
            }
          }
        }
        
        stateless_rule {
          priority = 2
          rule_definition {
            actions = ["aws:drop"]
            match_attributes {
              source {
                address_definition = "0.0.0.0/0"
              }
              destination_port {
                from_port = 3389
                to_port   = 3389
              }
              protocols = [6]
            }
          }
        }
      }
    }
  }
  
  tags = {
    Name = "drop-remote-access"
  }
}

resource "aws_networkfirewall_rule_group" "block_domains" {
  count = var.enable_network_firewall ? 1 : 0
  
  capacity = 100
  name     = "block-malicious-domains"
  type     = "STATEFUL"
  
  rule_group {
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set {
          definition = [var.hub_vpc_cidr]
        }
      }
    }
    
    rules_source {
      rules_source_list {
        generated_rules_type = "DENYLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets              = var.blocked_domains
      }
    }
  }
  
  tags = {
    Name = "block-domains"
  }
}

# Route 53 Private Hosted Zone for Internal DNS
resource "aws_route53_zone" "internal" {
  name = var.internal_domain
  
  vpc {
    vpc_id = module.hub_vpc.vpc_id
  }
  
  tags = {
    Name = "internal-dns-zone"
  }
}

# VPC Flow Logs Aggregation
resource "aws_s3_bucket" "flow_logs_aggregation" {
  bucket = "${var.organization_name}-flow-logs-aggregation-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Name    = "flow-logs-aggregation"
    Purpose = "Centralized network logging"
  }
}

resource "aws_s3_bucket_versioning" "flow_logs_aggregation" {
  bucket = aws_s3_bucket.flow_logs_aggregation.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs_aggregation" {
  bucket = aws_s3_bucket.flow_logs_aggregation.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.networking.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "flow_logs_aggregation" {
  bucket = aws_s3_bucket.flow_logs_aggregation.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_logs_aggregation" {
  bucket = aws_s3_bucket.flow_logs_aggregation.id
  
  rule {
    id     = "archive-old-logs"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 2555  # 7 years for compliance
    }
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
