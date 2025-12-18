# 🛡️ Compliance Mapping: SOC2 & ISO 27001

This document maps the technical controls of this Landing Zone to the **AICPA SOC2 Type II** and **ISO/IEC 27001** frameworks. This mapping serves as primary evidence during a security audit.

| Control Category | Requirement Description | Mapped to File/Resource | Technical Implementation |
| :--- | :--- | :--- | :--- |
| **Encryption at Rest** | Data must be encrypted at rest to protect sensitive information. | `modules/rds/main.tf` | RDS storage is encrypted using AWS KMS (AES-256). Secrets Manager uses KMS for credential envelope encryption. |
| **Least Privilege** | Access controls must limit permissions to the minimum necessary. | `modules/security/main.tf` | Granular IAM Task Roles for ECS; Security Groups implement "Default Deny" with explicit ingress for ECS/RDS only. |
| **Monitoring & Audit** | Continuous logging, alerting, and audit trails must be in place. | `modules/vpc/main.tf` | VPC Flow Logs capture all IP traffic. CloudWatch Dashboard provides real-time observability and anomaly alerting. |
| **High Availability** | Systems must ensure uptime and disaster recovery. | `modules/rds/main.tf` | Multi-AZ RDS failover; 3-AZ VPC topology; 35-day automated backups with cross-region snapshot capability. |
| **Access Control** | Authentication and authorization must be enforced at the edge. | `modules/security/main.tf` | AWS WAF prevents OWASP Top 10 attacks. GuardDuty provides AI-driven threat detection for account anomalies. |
| **Incident Response** | Mechanisms for detecting and responding to service failures. | `RECOVERY.md` | CloudWatch Alarms trigger on metric breaches. `RECOVERY.md` provides playbooks for DB Point-in-Time recovery. |
| **Data Integrity** | Data must be protected from unauthorized modification or deletion. | `Bootstrap/main.tf` | S3 Versioning and MFA Delete capability; RDS Deletion Protection is enabled by default. |
| **Change Management** | Infrastructure changes must be controlled and auditable. | `.github/workflows/main.yml` | CI/CD pipeline enforces `tfsec` security scans, `tflint` policy checks, and Infracost reviews on every PR. |

---

### 🎓 Auditor Note
The resources defined in this repository are configured to exceed the "Minimum Viable Security" posture. For specific audit evidence, run `terraform state show [resource_name]` to verify the live configuration against these controls.



> **Disclaimer:** This platform provides the infrastructure controls necessary for compliance. Final certification depends on the user's operational policies and application-level logic.
