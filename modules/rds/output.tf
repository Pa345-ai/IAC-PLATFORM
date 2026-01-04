output "db_endpoint" {
  description = "RDS database endpoint for connections"
  value       = aws_db_instance.main.address
  sensitive   = true
}

output "secrets_arn" {
  description = "ARN of the Secrets Manager secret for DB credentials"
  value       = aws_secretsmanager_secret.db_password.arn
}
