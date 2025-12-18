terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    ### STEP 1: REPLACE THIS WITH THE S3 NAME FROM BOOTSTRAP OUTPUT ###
    bucket = "REPLACE_WITH_BOOTSTRAP_BUCKET_NAME"
    key    = "enterprise-landing-zone.tfstate"
    ### STEP 2: ENSURE THIS REGION MATCHES YOUR BOOTSTRAP REGION ###
    region = "us-east-1"
    dynamodb_table = "terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region
}

module "vpc" {
  source     = "./modules/vpc"
  app_name   = var.app_name
  aws_region = var.aws_region
}

module "security" {
  source             = "./modules/security"
  app_name           = var.app_name
  vpc_id             = module.vpc.vpc_id
  allowed_cidr       = var.allowed_cidr
  domain_name        = var.domain_name
  public_subnet_ids  = module.vpc.public_subnet_ids
}

module "rds" {
  source            = "./modules/rds"
  app_name          = var.app_name
  db_name           = var.db_name
  db_username       = var.db_username
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  security_group_id = module.security.rds_sg_id
}

module "ecs" {
  source             = "./modules/ecs"
  app_name           = var.app_name
  aws_region         = var.aws_region
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnet_ids
  security_group_id  = module.security.ecs_sg_id
  target_group_arn   = module.security.target_group_arn
  db_endpoint        = module.rds.db_endpoint
  db_name            = var.db_name
  db_username        = var.db_username
  secrets_arn        = module.rds.secrets_arn
  desired_count      = var.desired_count
  alb_arn_suffix     = module.security.alb_arn_suffix
  db_instance_id     = module.rds.db_instance_id
}
