# environments/global/security/outputs.tf

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "security_hub_arn" {
  description = "Security Hub ARN"
  value       = aws_securityhub_account.main.id
}

output "config_recorder_id" {
  description = "AWS Config recorder ID"
  value       = aws_config_configuration_recorder.main.id
}

output "security_kms_key_arn" {
  description = "KMS key ARN for security services"
  value       = aws_kms_key.security.arn
}

output "security_alerts_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "config_changes_topic_arn" {
  description = "SNS topic ARN for config changes"
  value       = aws_sns_topic.config_changes.arn
}
