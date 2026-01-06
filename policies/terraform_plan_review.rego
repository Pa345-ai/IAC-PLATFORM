package terraform.plan_review

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Comprehensive Terraform Plan Review
# description: Master policy that validates all aspects of infrastructure changes
# custom:
#   severity: ADVISORY
#   compliance: ["ALL"]

# Import other policies
import data.terraform.data_residency
import data.terraform.encryption_enforcement
import data.terraform.iam_boundary_check

################################################################################
# Resource Count Limits
################################################################################

# Warn if creating too many resources at once
warn[msg] {
    resource_changes := input.resource_changes
    create_count := count([r | r := resource_changes[_]; "create" in r.change.actions])
    create_count > 50
    
    msg := sprintf(
        "WARNING: Plan creates %d resources. Consider breaking into smaller changes.",
        [create_count]
    )
}

# Warn if destroying critical resources
deny[msg] {
    resource := input.resource_changes[_]
    "delete" in resource.change.actions
    
    critical_types := {
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_s3_bucket",
        "aws_kms_key"
    }
    
    resource.type in critical_types
    
    # Allow if it's a test environment
    not contains(resource.name, "test")
    not contains(resource.name, "dev")
    
    msg := sprintf(
        "CRITICAL: Attempting to delete critical resource %s '%s'. Manual review required.",
        [resource.type, resource.name]
    )
}

################################################################################
# Cost Estimation
################################################################################

# Warn about expensive instance types
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    "create" in resource.change.actions
    
    expensive_types := {
        "r5.16xlarge",
        "r5.24xlarge",
        "x1.32xlarge",
        "x1e.32xlarge",
        "p3.16xlarge",
        "p4d.24xlarge"
    }
    
    instance_type := resource.change.after.instance_type
    instance_type in expensive_types
    
    msg := sprintf(
        "COST WARNING: Creating expensive instance type '%s' for resource '%s'. Estimated cost: $10,000+/month",
        [instance_type, resource.name]
    )
}

# Warn about large storage allocations
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    "create" in resource.change.actions
    
    storage := resource.change.after.allocated_storage
    storage > 5000
    
    msg := sprintf(
        "COST WARNING: RDS instance '%s' allocated storage is %d GB. Review capacity requirements.",
        [resource.name, storage]
    )
}

################################################################################
# Tagging Compliance
################################################################################

required_tags := ["Environment", "ManagedBy", "CostCenter", "Compliance"]

deny[msg] {
    resource := input.resource_changes[_]
    "create" in resource.change.actions
    
    taggable_resources := {
        "aws_instance",
        "aws_db_instance",
        "aws_s3_bucket",
        "aws_vpc",
        "aws_subnet",
        "aws_security_group",
        "aws_kms_key"
    }
    
    resource.type in taggable_resources
    
    tags := object.get(resource.change.after, "tags", {})
    
    missing_tag := required_tags[_]
    not tags[missing_tag]
    
    msg := sprintf(
        "TAGGING: Resource %s '%s' is missing required tag: %s",
        [resource.type, resource.name, missing_tag]
    )
}

################################################################################
# Security Best Practices
################################################################################

# Deny public S3 buckets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    "create" in resource.change.actions
    
    config := resource.change.after
    
    not config.block_public_acls
    not config.block_public_policy
    not config.ignore_public_acls
    not config.restrict_public_buckets
    
    msg := sprintf(
        "SECURITY: S3 bucket '%s' allows public access. All blocks must be enabled.",
        [resource.name]
    )
}

# Deny security groups with wide-open access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    "create" in resource.change.actions
    
    ingress := resource.change.after.ingress[_]
    
    contains_cidr(ingress.cidr_blocks, "0.0.0.0/0")
    dangerous_port(ingress.from_port, ingress.to_port)
    
    msg := sprintf(
        "SECURITY: Security group '%s' allows 0.0.0.0/0 access to dangerous port range %d-%d",
        [resource.name, ingress.from_port, ingress.to_port]
    )
}

contains_cidr(cidrs, target) {
    cidrs[_] == target
}

dangerous_port(from, to) {
    dangerous_ports := {22, 3389, 3306, 5432, 1433, 27017}
    port := dangerous_ports[_]
    port >= from
    port <= to
}

# Warn about default VPC usage
warn[msg] {
    resource := input.resource_changes[_]
    resource.type in ["aws_instance", "aws_db_instance"]
    "create" in resource.change.actions
    
    vpc_id := resource.change.after.vpc_id
    contains(vpc_id, "default")
    
    msg := sprintf(
        "BEST PRACTICE: Resource '%s' uses default VPC. Use custom VPCs for production.",
        [resource.name]
    )
}

################################################################################
# High Availability Checks
################################################################################

# Warn if RDS is not multi-AZ in production
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    "create" in resource.change.actions
    
    contains(resource.name, "prod")
    
    multi_az := object.get(resource.change.after, "multi_az", false)
    not multi_az
    
    msg := sprintf(
        "HIGH AVAILABILITY: Production RDS instance '%s' should have multi_az enabled",
        [resource.name]
    )
}

# Warn if EKS has less than 3 nodes in production
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_eks_node_group"
    "create" in resource.change.actions
    
    contains(resource.name, "prod")
    
    scaling := resource.change.after.scaling_config[_]
    desired := scaling.desired_size
    desired < 3
    
    msg := sprintf(
        "HIGH AVAILABILITY: Production EKS node group '%s' should have at least 3 nodes (currently %d)",
        [resource.name, desired]
    )
}

################################################################################
# Backup and Recovery
################################################################################

# Deny RDS without backups
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    "create" in resource.change.actions
    
    backup_retention := object.get(resource.change.after, "backup_retention_period", 0)
    backup_retention == 0
    
    msg := sprintf(
        "BACKUP: RDS instance '%s' must have backup_retention_period > 0 (PCI-DSS requirement)",
        [resource.name]
    )
}

# Warn if backup retention is too short for production
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    "create" in resource.change.actions
    
    contains(resource.name, "prod")
    
    backup_retention := object.get(resource.change.after, "backup_retention_period", 0)
    backup_retention < 30
    
    msg := sprintf(
        "BACKUP: Production RDS instance '%s' should have backup_retention_period >= 30 days (currently %d)",
        [resource.name, backup_retention]
    )
}

################################################################################
# Monitoring and Logging
################################################################################

# Warn if CloudWatch logging is not enabled
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    "create" in resource.change.actions
    
    logs := object.get(resource.change.after, "enabled_cloudwatch_logs_exports", [])
    count(logs) == 0
    
    msg := sprintf(
        "MONITORING: RDS instance '%s' should enable CloudWatch log exports for audit compliance",
        [resource.name]
    )
}

################################################################################
# Network Architecture
################################################################################

# Deny resources in wrong subnet tiers
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    "create" in resource.change.actions
    
    subnet_group := resource.change.after.db_subnet_group_name
    
    # Databases should be in data subnets
    not contains(subnet_group, "data")
    
    msg := sprintf(
        "NETWORK: Database '%s' must use data subnet group (currently: %s)",
        [resource.name, subnet_group]
    )
}

################################################################################
# Change Impact Analysis
################################################################################

# Calculate change summary
change_summary[result] {
    changes := input.resource_changes
    
    create_count := count([r | r := changes[_]; "create" in r.change.actions])
    update_count := count([r | r := changes[_]; "update" in r.change.actions])
    delete_count := count([r | r := changes[_]; "delete" in r.change.actions])
    
    result := {
        "total_changes": count(changes),
        "creates": create_count,
        "updates": update_count,
        "deletes": delete_count,
        "risk_level": risk_level(create_count, update_count, delete_count)
    }
}

risk_level(creates, updates, deletes) := "HIGH" {
    deletes > 0
}

risk_level(creates, updates, deletes) := "MEDIUM" {
    deletes == 0
    creates + updates > 20
}

risk_level(creates, updates, deletes) := "LOW" {
    deletes == 0
    creates + updates <= 20
}

################################################################################
# Comprehensive Report
################################################################################

plan_review_report[result] {
    result := {
        "encryption_status": data.terraform.encryption_enforcement.encryption_compliance_report,
        "data_residency_status": data.terraform.data_residency.compliance_report,
        "iam_status": data.terraform.iam_boundary_check.iam_compliance_report,
        "change_summary": change_summary,
        "policy_version": "1.0.0",
        "review_timestamp": time.now_ns()
    }
}
