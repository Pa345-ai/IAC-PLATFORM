# environments/global/networking/outputs.tf

output "hub_vpc_id" {
  description = "ID of the hub VPC"
  value       = module.hub_vpc.vpc_id
}

output "hub_vpc_cidr" {
  description = "CIDR block of hub VPC"
  value       = module.hub_vpc.vpc_cidr
}

output "transit_gateway_id" {
  description = "ID of the Transit Gateway"
  value       = aws_ec2_transit_gateway.main.id
}

output "transit_gateway_arn" {
  description = "ARN of the Transit Gateway"
  value       = aws_ec2_transit_gateway.main.arn
}

output "shared_services_route_table_id" {
  description = "Transit Gateway route table for shared services"
  value       = aws_ec2_transit_gateway_route_table.shared_services.id
}

output "production_route_table_id" {
  description = "Transit Gateway route table for production"
  value       = aws_ec2_transit_gateway_route_table.production.id
}

output "non_production_route_table_id" {
  description = "Transit Gateway route table for non-production"
  value       = aws_ec2_transit_gateway_route_table.non_production.id
}

output "networking_kms_key_id" {
  description = "KMS key ID for network encryption"
  value       = aws_kms_key.networking.key_id
}

output "networking_kms_key_arn" {
  description = "KMS key ARN for network encryption"
  value       = aws_kms_key.networking.arn
}

output "internal_dns_zone_id" {
  description = "Route53 private hosted zone ID"
  value       = aws_route53_zone.internal.zone_id
}

output "internal_domain" {
  description = "Internal domain name"
  value       = aws_route53_zone.internal.name
}

output "flow_logs_bucket" {
  description = "S3 bucket for centralized flow logs"
  value       = aws_s3_bucket.flow_logs_aggregation.id
}
