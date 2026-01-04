output "ecs_service_url" {
  description = "HTTPS URL of the ALB to access the demo app"
  value       = "https://${module.security.alb_dns}"
}

output "db_endpoint" {
  description = "RDS database endpoint"
  value       = module.rds.db_endpoint
  sensitive   = true
}

output "vpc_id" {
  description = "VPC ID for future expansions"
  value       = module.vpc.vpc_id
}

output "security_group_ids" {
  description = "Security Group IDs for ALB, ECS, and RDS"
  value       = module.security.sg_ids
}

output "secrets_arn" {
  description = "ARN of the Secrets Manager secret for DB credentials"
  value       = module.rds.secrets_arn
}

output "route53_nameservers" {
  description = "Route53 nameservers for domain registrar"
  value       = module.security.route53_nameservers
}
