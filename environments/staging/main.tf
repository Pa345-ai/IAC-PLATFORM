# environments/staging/main.tf
# Staging Environment - Production-like with Cost Optimization

terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  environment = "staging"
  
  common_tags = {
    Environment = local.environment
    ManagedBy   = "terraform"
    Repository  = "sovereign-cloud-archive"
    CostCenter  = "staging"
    Compliance  = "pci-dss-nist-soc2"
  }
}

# Data Sources
data "terraform_remote_state" "global_networking" {
  backend = "s3"
  
  config = {
    bucket = var.tfstate_bucket
    key    = "global/networking/terraform.tfstate"
    region = var.aws_region
  }
}

data "terraform_remote_state" "global_iam" {
  backend = "s3"
  
  config = {
    bucket = var.tfstate_bucket
    key    = "global/iam/terraform.tfstate"
    region = var.aws_region
  }
}

data "aws_caller_identity" "current" {}

################################################################################
# VPC and Networking
################################################################################

module "vpc" {
  source = "../../modules/networking/vpc"
  
  environment             = local.environment
  vpc_cidr                = var.vpc_cidr
  multi_az                = true
  enable_flow_logs        = true
  enable_vpc_endpoints    = true
  flow_log_retention_days = 90
  kms_key_arn            = module.kms.encryption_key_arn
  
  tags = local.common_tags
}

# Transit Gateway Attachment
resource "aws_ec2_transit_gateway_vpc_attachment" "staging" {
  subnet_ids         = module.vpc.private_subnet_ids
  transit_gateway_id = data.terraform_remote_state.global_networking.outputs.transit_gateway_id
  vpc_id             = module.vpc.vpc_id
  
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
  
  tags = merge(local.common_tags, {
    Name = "${local.environment}-tgw-attachment"
  })
}

resource "aws_ec2_transit_gateway_route_table_association" "staging" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.staging.id
  transit_gateway_route_table_id = data.terraform_remote_state.global_networking.outputs.non_production_route_table_id
}

################################################################################
# KMS Encryption
################################################################################

module "kms" {
  source = "../../modules/security/kms"
  
  environment         = local.environment
  key_name            = "staging-master-key"
  enable_key_rotation = true
  deletion_window     = 30
  
  key_administrators = [
    data.terraform_remote_state.global_iam.outputs.admin_role_arn
  ]
  
  key_users = [
    data.terraform_remote_state.global_iam.outputs.eks_cluster_role_arn,
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
  ]
  
  tags = local.common_tags
}

################################################################################
# EKS Cluster
################################################################################

module "eks" {
  source = "../../modules/compute/eks"
  
  environment    = local.environment
  cluster_name   = "${local.environment}-eks-cluster"
  cluster_version = "1.28"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnet_ids
  
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true  # Staging: Allow public for testing
  
  cluster_encryption_config = {
    provider_key_arn = module.kms.encryption_key_arn
    resources        = ["secrets"]
  }
  
  cluster_enabled_log_types = ["api", "audit"]
  
  # Smaller node groups for staging
  node_groups = {
    application = {
      desired_size   = 2
      min_size       = 2
      max_size       = 5
      instance_types = ["m5.large"]
      disk_size      = 50
      disk_encrypted = true
      disk_kms_key_id = module.kms.encryption_key_arn
      
      labels = {
        role = "application"
      }
    }
  }
  
  cluster_role_arn           = data.terraform_remote_state.global_iam.outputs.eks_cluster_role_arn
  node_role_arn              = data.terraform_remote_state.global_iam.outputs.eks_node_role_arn
  node_instance_profile_name = data.terraform_remote_state.global_iam.outputs.eks_node_instance_profile
  
  tags = local.common_tags
}

################################################################################
# RDS Database
################################################################################

module "rds" {
  source = "../../modules/data/rds"
  
  environment = local.environment
  identifier  = "${local.environment}-db"
  
  engine               = "aurora-postgresql"
  engine_version       = "15.4"
  instance_class       = "db.r6g.large"
  allocated_storage    = 100
  max_allocated_storage = 500
  storage_encrypted    = true
  kms_key_id          = module.kms.encryption_key_arn
  
  multi_az                = true
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"
  
  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.data_subnet_ids
  allowed_cidr_blocks = module.vpc.private_subnet_cidrs
  
  performance_insights_enabled = true
  monitoring_interval          = 60
  monitoring_role_arn          = data.terraform_remote_state.global_iam.outputs.rds_monitoring_role_arn
  
  tags = local.common_tags
}

################################################################################
# Application Load Balancer
################################################################################

resource "aws_lb" "staging" {
  name               = "${local.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnet_ids
  
  enable_deletion_protection = false  # Staging: Allow deletion
  
  tags = local.common_tags
}

resource "aws_security_group" "alb" {
  name_prefix = "${local.environment}-alb-"
  description = "Security group for staging load balancer"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = local.common_tags
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "eks_cluster_endpoint" {
  value     = module.eks.cluster_endpoint
  sensitive = true
}

output "rds_endpoint" {
  value     = module.rds.db_instance_endpoint
  sensitive = true
}
