# Day 2 Recovery Playbook

This document contains "Break-Glass" procedures for critical infrastructure recovery. Ensure you have the `AdministratorAccess` IAM policy attached to your CLI session before proceeding.

---

## 1. RDS Point-in-Time Restore (PITR)

**Description:** Use this procedure if the database suffers data corruption or accidental table deletion. AWS RDS allows restoration to any specific second within your retention period.

**Execution:**
1. Verify your source DB has backup retention enabled:
   `aws rds describe-db-instances --db-instance-identifier <source-id> --query 'DBInstances[*].BackupRetentionPeriod'`

2. Run the restoration command:

```bash
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier <your-db-instance-id> \
  --target-db-instance-identifier <new-db-instance-name> \
  --restore-time 2025-12-18T12:00:00Z \
  --db-instance-class db.t3.micro \
  --db-subnet-group-name <your-subnet-group> \
  --vpc-security-group-ids <your-sg-id>
Post-Recovery Note: This creates a NEW instance. You must update the connection strings in AWS Secrets Manager or your application environment variables to point to the new endpoint once the status is available.

2. ECS Service Rollback
Description: Use this when a new application deployment fails or introduces a critical bug. This forces the ECS service to revert to a previously known-good Task Definition.

Execution:

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
Description: Use this if the Web Application Firewall (WAF) is blocking legitimate traffic (false positives) during a critical event and immediate access is required.

Execution:

Bash

# 1. Get the current lock token (required for updates)
TOKEN=$(aws wafv2 get-web-acl --name <your-waf-name> --scope REGIONAL --id <your-waf-id> --query 'LockToken' --output text)

# 2. Clear rules to allow all traffic (Emergency Mode)
aws wafv2 update-web-acl \
  --name <your-waf-name> \
  --scope REGIONAL \
  --id <your-waf-id> \
  --default-action Allow={} \
  --rules '[]' \
  --lock-token $TOKEN
4. S3 State Recovery
Description: Use this if the Terraform State file is accidentally deleted or corrupted. This prevents "orphaning" your infrastructure.

Execution: Because versioning is enabled in the Bootstrap configuration, you can recover any previous state file version:

Identify the version ID:

Bash

aws s3api list-object-versions --bucket <state-bucket> --prefix terraform.tfstate
Restore the object:

Bash

aws s3api copy-object \
  --copy-source <bucket>/terraform.tfstate?versionId=<id> \
  --bucket <bucket> \
  --key terraform.tfstate
Support & Escalation
For high-priority infrastructure failure, verify logs in CloudWatch Logs under the /aws/ecs/ or /aws/rds/ namespaces before initiating recovery procedures. Reference the Compliance Mapping document for resource-specific security configurations.


---

### Why this is the "Sales-Winning" Version:
* **Structured Layout:** By using `---` and `##`, it creates a visual separation that looks like a printed manual.
* **Technical Precision:** It includes the `TOKEN` variable logic and multi-line bash formatting (with `\`) which is standard for high-end documentation.
* **Clear Instructions:** Each section has a **Description** and **Execution** header, making it easy to read under pressure.

**Would you like me to help you create the final zip file structure so you can hand this over to the buyer today?**
