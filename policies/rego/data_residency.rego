package terraform.data_residency

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Data Residency Enforcement Policy
# description: Ensures all resources are deployed only in approved regions per NIST 800-53 SC-7
# custom:
#   severity: CRITICAL
#   compliance: ["NIST-800-53", "PCI-DSS-12.8", "GDPR-Article-32"]

# Approved regions for banking operations (US-only for this example)
approved_regions := {
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2"
}

# Critical resources that MUST comply with data residency
critical_resources := {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_s3_bucket",
    "aws_ebs_volume",
    "aws_efs_file_system",
    "aws_dynamodb_table",
    "aws_redshift_cluster",
    "aws_elasticsearch_domain",
    "aws_kms_key"
}

# Deny if resource is created in non-approved region
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in critical_resources
    resource.change.actions[_] == "create"
    
    provider_config := resource.provider_name
    region := provider_region(provider_config)
    
    not region in approved_regions
    
    msg := sprintf(
        "CRITICAL: %s '%s' is being created in non-approved region '%s'. Approved regions: %v",
        [resource.type, resource.name, region, approved_regions]
    )
}

# Deny if provider is configured with non-approved region
deny[msg] {
    provider := input.configuration.provider_config[_]
    provider.name == "aws"
    
    region := object.get(provider.expressions, "region", {})
    region_value := object.get(region, "constant_value", "")
    
    region_value != ""
    not region_value in approved_regions
    
    msg := sprintf(
        "CRITICAL: AWS provider configured with non-approved region '%s'. Approved regions: %v",
        [region_value, approved_regions]
    )
}

# Check for multi-region resources
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    replication := object.get(resource.change.after, "replication_configuration", [])
    count(replication) > 0
    
    # Verify all replication destinations are approved
    dest_region := replication[_].rules[_].destination[_].region
    not dest_region in approved_regions
    
    msg := sprintf(
        "CRITICAL: S3 bucket '%s' replicates to non-approved region '%s'",
        [resource.name, dest_region]
    )
}

# Verify backup destinations
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_backup_plan"
    
    rule := resource.change.after.rule[_]
    copy_action := rule.copy_action[_]
    dest_region := copy_action.destination_backup_vault_arn
    
    # Extract region from ARN
    region := split(dest_region, ":")[3]
    not region in approved_regions
    
    msg := sprintf(
        "CRITICAL: Backup plan '%s' copies to non-approved region '%s'",
        [resource.name, region]
    )
}

# Check for global resources that might leak data
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudfront_distribution"
    
    msg := sprintf(
        "WARNING: CloudFront distribution '%s' is global - ensure geo-restrictions are configured",
        [resource.name]
    )
}

# Verify KMS keys are regional
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_kms_key"
    
    multi_region := object.get(resource.change.after, "multi_region", false)
    multi_region == true
    
    msg := sprintf(
        "CRITICAL: KMS key '%s' is configured as multi-region. This violates data residency requirements.",
        [resource.name]
    )
}

# Helper function to extract region from provider configuration
provider_region(provider_name) := region {
    provider := input.configuration.provider_config[provider_name]
    region := object.get(provider.expressions.region, "constant_value", "unknown")
}

# Compliance report
compliance_report[result] {
    total_resources := count(input.resource_changes)
    critical_count := count([r | r := input.resource_changes[_]; r.type in critical_resources])
    
    result := {
        "total_resources": total_resources,
        "critical_resources": critical_count,
        "approved_regions": approved_regions,
        "policy": "Data Residency Enforcement",
        "compliance_frameworks": ["NIST-800-53-SC-7", "PCI-DSS-12.8", "GDPR-Article-32"]
    }
}
