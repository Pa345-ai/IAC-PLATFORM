# modules/security/kms/main.tf
# Bank-Grade KMS Key Management

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
data "aws_region" "current" {}

locals {
  key_administrators = concat(
    var.key_administrators,
    ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
  )
  
  key_users = concat(
    var.key_users,
    var.service_principals
  )
}

################################################################################
# KMS Customer Managed Key
################################################################################

resource "aws_kms_key" "main" {
  description              = var.key_description != "" ? var.key_description : "KMS key for ${var.environment} ${var.key_name}"
  deletion_window_in_days  = var.deletion_window
  enable_key_rotation      = var.enable_key_rotation
  multi_region             = var.multi_region
  customer_master_key_spec = var.key_spec
  key_usage                = var.key_usage
  
  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-${var.key_name}"
      Environment = var.environment
      Purpose     = var.key_purpose
    }
  )
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.environment}/${var.key_name}"
  target_key_id = aws_kms_key.main.key_id
}

################################################################################
# KMS Key Policy
################################################################################

resource "aws_kms_key_policy" "main" {
  key_id = aws_kms_key.main.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "${var.environment}-${var.key_name}-policy"
    Statement = concat(
      [
        # Root account access (required)
        {
          Sid    = "Enable IAM User Permissions"
          Effect = "Allow"
          Principal = {
            AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          }
          Action   = "kms:*"
          Resource = "*"
        },
        
        # Key administrators
        {
          Sid    = "Allow key administrators to manage the key"
          Effect = "Allow"
          Principal = {
            AWS = local.key_administrators
          }
          Action = [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion"
          ]
          Resource = "*"
        },
        
        # Key users - encryption/decryption
        {
          Sid    = "Allow key users to encrypt and decrypt data"
          Effect = "Allow"
          Principal = {
            AWS = [for arn in local.key_users : arn if !can(regex("^[a-z]+\\.[a-z-]+\\.amazonaws\\.com$", arn))]
          }
          Action = [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:CreateGrant",
            "kms:DescribeKey"
          ]
          Resource = "*"
        },
        
        # CloudWatch Logs
        {
          Sid    = "Allow CloudWatch Logs to use the key"
          Effect = "Allow"
          Principal = {
            Service = "logs.${data.aws_region.current.name}.amazonaws.com"
          }
          Action = [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:CreateGrant",
            "kms:DescribeKey"
          ]
          Resource = "*"
          Condition = {
            ArnLike = {
              "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            }
          }
        },
        
        # S3
        {
          Sid    = "Allow S3 to use the key"
          Effect = "Allow"
          Principal = {
            Service = "s3.amazonaws.com"
          }
          Action = [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ]
          Resource = "*"
        },
        
        # RDS
        {
          Sid    = "Allow RDS to use the key"
          Effect = "Allow"
          Principal = {
            Service = "rds.amazonaws.com"
          }
          Action = [
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:CreateGrant"
          ]
          Resource = "*"
        },
        
        # EBS
        {
          Sid    = "Allow EBS to use the key"
          Effect = "Allow"
          Principal = {
            Service = "ec2.amazonaws.com"
          }
          Action = [
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:CreateGrant"
          ]
          Resource = "*"
          Condition = {
            StringEquals = {
              "kms:ViaService" = "ec2.${data.aws_region.current.name}.amazonaws.com"
            }
          }
        }
      ],
      
      # Service principals
      length(var.service_principals) > 0 ? [{
        Sid    = "Allow AWS services to use the key"
        Effect = "Allow"
        Principal = {
          Service = var.service_principals
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }] : []
    )
  })
}

################################################################################
# CloudWatch Alarms for Key Usage
################################################################################

resource "aws_cloudwatch_metric_alarm" "key_deletion_scheduled" {
  count = var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${var.environment}-${var.key_name}-deletion-scheduled"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ScheduledKeyDeletion"
  namespace           = "AWS/KMS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alert when KMS key deletion is scheduled"
  treat_missing_data  = "notBreaching"
  
  dimensions = {
    KeyId = aws_kms_key.main.key_id
  }
  
  alarm_actions = var.alarm_sns_topic_arns
  
  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "key_disabled" {
  count = var.enable_monitoring ? 1 : 0
  
  alarm_name          = "${var.environment}-${var.key_name}-disabled"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "KeyState"
  namespace           = "AWS/KMS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alert when KMS key is disabled"
  treat_missing_data  = "notBreaching"
  
  dimensions = {
    KeyId = aws_kms_key.main.key_id
  }
  
  alarm_actions = var.alarm_sns_topic_arns
  
  tags = var.tags
}

################################################################################
# Grants for Service Integration
################################################################################

resource "aws_kms_grant" "service_grants" {
  for_each = var.service_grants
  
  name              = each.key
  key_id            = aws_kms_key.main.key_id
  grantee_principal = each.value.grantee_principal
  operations        = each.value.operations
  
  dynamic "constraints" {
    for_each = lookup(each.value, "encryption_context_equals", null) != null ? [1] : []
    content {
      encryption_context_equals = each.value.encryption_context_equals
    }
  }
  
  dynamic "constraints" {
    for_each = lookup(each.value, "encryption_context_subset", null) != null ? [1] : []
    content {
      encryption_context_subset = each.value.encryption_context_subset
    }
  }
}
