# Day 2 Recovery Guide



This guide provides step-by-step CLI commands for common recovery scenarios. Run these with AWS CLI configured.



## RDS Point-in-Time Restore

To restore the database to a specific timestamp (e.g., 2023-10-01T12:00:00Z):

aws rds restore-db-instance-to-point-in-time

--source-db-instance-identifier <your-db-instance-id>

--target-db-instance-identifier <new-db-name>

--restore-time 2023-10-01T12:00:00Z

--db-instance-class db.t3.micro

--db-subnet-group-name <your-subnet-group>

--vpc-security-group-ids <your-sg-id>

--no-multi-az

--no-deletion-protection






- Replace placeholders with values from Terraform outputs.

- This creates a new DB instance; update ECS secrets if needed.



## ECS Rollback to Previous Image

To roll back ECS service to a previous ECR image tag (e.g., v1.0):

aws ecs update-service

--cluster <your-cluster-name>

--service <your-service-name>

--force-new-deployment

--task-definition <previous-task-def-arn>






- Find previous task definition ARN in AWS console or CLI: `aws ecs list-task-definitions --family-prefix <your-task-family>`.

- Update the task definition JSON with the old image tag before registering.



## Emergency WAF Bypass (Break-Glass)

To temporarily disable WAF for troubleshooting:

aws wafv2 update-web-acl

--name <your-waf-name>

--scope REGIONAL

--id <your-waf-id>

--default-action Block={}

--rules '[]' # Empty rules to bypass






- Re-enable by restoring original rules. Use with caution; monitor closely.



For full disaster recovery, refer to AWS Backup for cross-region restores.

