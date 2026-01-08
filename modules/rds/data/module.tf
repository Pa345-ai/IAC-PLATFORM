# modules/data/rds/main.tf
# Encrypted Multi-AZ RDS Database Module

terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

################################################################################
# DB Subnet Group
################################################################################

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-${var.identifier}-subnet-group"
  subnet_ids = var.subnet_ids
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-${var.identifier}-subnet-group"
    }
  )
}

################################################################################
# DB Parameter Group
################################################################################

resource "aws_db_parameter_group" "main" {
  count = var.family != null ? 1 : 0
  
  name   = "${var.environment}-${var.identifier}-params"
  family = var.family
  
  dynamic "parameter" {
    for_each = var.parameters
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = lookup(parameter.value, "apply_method", "immediate")
    }
  }
  
  tags = var.tags
  
  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "rds" {
  name_prefix = "${var.environment}-${var.identifier}-"
  description = "Security group for RDS database ${var.identifier}"
  vpc_id      = var.vpc_id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-${var.identifier}-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "ingress" {
  security_group_id = aws_security_group.rds.id
  type              = "ingress"
  from_port         = var.port
  to_port           = var.port
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidr_blocks
  description       = "Allow database access from application tier"
}

resource "aws_security_group_rule" "egress" {
  security_group_id = aws_security_group.rds.id
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow all outbound traffic"
}

################################################################################
# RDS Instance
################################################################################

resource "aws_db_instance" "main" {
  count = var.replicate_source_db == null ? 1 : 0
  
  identifier = var.identifier
  
  # Engine
  engine               = var.engine
  engine_version       = var.engine_version
  instance_class       = var.instance_class
  allocated_storage    = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type         = var.storage_type
  storage_encrypted    = var.storage_encrypted
  kms_key_id          = var.kms_key_id
  
  # Database
  db_name  = var.db_name
  username = var.username
  password = var.password
  port     = var.port
  
  # Network
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  
  # High Availability
  multi_az = var.multi_az
  
  # Backup
  backup_retention_period = var.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window
  
  # Monitoring
  enabled_cloudwatch_logs_exports = var.enabled_cloudwatch_logs_exports
  performance_insights_enabled    = var.performance_insights_enabled
  performance_insights_kms_key_id = var.performance_insights_kms_key_id
  monitoring_interval             = var.monitoring_interval
  monitoring_role_arn             = var.monitoring_role_arn
  
  # Parameters
  parameter_group_name = var.family != null ? aws_db_parameter_group.main[0].name : null
  
  # Protection
  deletion_protection       = var.deletion_protection
  skip_final_snapshot      = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${var.identifier}-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  copy_tags_to_snapshot    = true
  
  # Upgrades
  auto_minor_version_upgrade = var.auto_minor_version_upgrade
  apply_immediately         = var.apply_immediately
  
  tags = merge(
    var.tags,
    {
      Name = var.identifier
    }
  )
  
  lifecycle {
    ignore_changes = [
      password,
      final_snapshot_identifier
    ]
  }
}

################################################################################
# Read Replica
################################################################################

resource "aws_db_instance" "replica" {
  count = var.replicate_source_db != null ? 1 : 0
  
  identifier             = var.identifier
  replicate_source_db    = var.replicate_source_db
  instance_class         = var.instance_class
  storage_encrypted      = var.storage_encrypted
  kms_key_id            = var.kms_key_id
  
  # Network
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  
  # Backup (replicas can have their own backup config)
  backup_retention_period = var.backup_retention_period
  
  # Monitoring
  performance_insights_enabled    = var.performance_insights_enabled
  performance_insights_kms_key_id = var.performance_insights_kms_key_id
  monitoring_interval             = var.monitoring_interval
  monitoring_role_arn             = var.monitoring_role_arn
  
  # Protection
  deletion_protection       = var.deletion_protection
  skip_final_snapshot      = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${var.identifier}-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  # Upgrades
  auto_minor_version_upgrade = var.auto_minor_version_upgrade
  apply_immediately         = var.apply_immediately
  
  tags = merge(
    var.tags,
    {
      Name = var.identifier
      Type = "ReadReplica"
    }
  )
  
  lifecycle {
    ignore_changes = [
      final_snapshot_identifier
    ]
  }
}
