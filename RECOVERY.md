# Day 2 Recovery Playbook



This document contains "Break-Glass" procedures for critical infrastructure recovery. Ensure you have the AdministratorAccess IAM policy attached to your CLI session before proceeding.



---



## 1. RDS Point-in-Time Restore (PITR)

**Use Case:** Data corruption or accidental table deletion.



### Pre-flight Check

Verify your source DB has backup retention enabled:

`aws rds describe-db-instances --db-instance-identifier <source-id> --query 'DBInstances[*].BackupRetentionPeriod'`







### Execution

```bash

aws rds restore-db-instance-to-point-in-time \

  --source-db-instance-identifier <your-db-instance-id> \

  --target-db-instance-identifier <new-db-instance-name> \

  --restore-time 2025-12-18T12:00:00Z \

  --db-instance-class db.t3.micro \

  --db-subnet-group-name <your-subnet-group> \

  --vpc-security-group-ids <your-sg-id>

Note: This creates a NEW instance. You must update the connection strings in AWS Secrets Manager to point to the new endpoint once the restore is complete.



2. ECS Service Rollback

Use Case: Failed application deployment or critical bug in the latest container.



Execution

Bash



# 1. List previous versions to find the known-good ARN

aws ecs list-task-definitions --family-prefix <your-task-family>



# 2. Force rollback to the stable ARN

aws ecs update-service \

  --cluster <your-cluster-name> \

  --service <your-service-name> \

  --task-definition <previous-task-def-arn> \

  --force-new-deployment

3. Emergency WAF Break-Glass

Use Case: WAF is blocking legitimate traffic (False Positives) during a critical event.



Execution

Bash



# 1. Get the current lock token (required for updates)

TOKEN=$(aws wafv2 get-web-acl --name <your-waf-name> --scope REGIONAL --id <your-waf-id> --query 'LockToken' --output text)



# 2. Clear rules to allow all traffic

aws wafv2 update-web-acl \

  --name <your-waf-name> \

  --scope REGIONAL \

  --id <your-waf-id> \

  --default-action Allow={} \

  --rules '[]' \

  --lock-token $TOKEN

4. S3 State Recovery

Use Case: Accidental deletion of the Terraform State file.



Because versioning is enabled in the Bootstrap configuration, you can recover any previous state file version:



Identify the version ID: aws s3api list-object-versions --bucket <state-bucket> --prefix terraform.tfstate



Restore the object: aws s3api copy-object --copy-source <bucket>/terraform.tfstate?versionId=<id> --bucket <bucket> --key terraform.tfstate



Support & Escalation

For high-priority infrastructure failure, verify logs in CloudWatch Logs under the /aws/ecs/ or /aws/rds/ namespaces before initiating recovery procedures.





---


