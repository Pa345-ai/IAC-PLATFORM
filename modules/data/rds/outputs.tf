# modules/data/rds/outputs.tf

output "db_instance_id" {
  description = "RDS instance ID"
  value       = var.replicate_source_db == null ? aws_db_instance.main[0].id : aws_db_instance.replica[0].id
}

output "db_instance_arn" {
  description = "RDS instance ARN"
  value       = var.replicate_source_db == null ? aws_db_instance.main[0].arn : aws_db_instance.replica[0].arn
}

output "db_instance_endpoint" {
  description = "Connection endpoint"
  value       = var.replicate_source_db == null ? aws_db_instance.main[0].endpoint : aws_db_instance.replica[0].endpoint
}

output "db_instance_address" {
  description = "Hostname of the RDS instance"
  value       = var.replicate_source_db == null ? aws_db_instance.main[0].address : aws_db_instance.replica[0].address
}

output "db_instance_port" {
  description = "Database port"
  value       = var.replicate_source_db == null ? aws_db_instance.main[0].port : aws_db_instance.replica[0].port
}

output "db_security_group_id" {
  description = "Security group ID for database"
  value       = aws_security_group.rds.id
}

output "db_subnet_group_name" {
  description = "Database subnet group name"
  value       = aws_db_subnet_group.main.name
}
