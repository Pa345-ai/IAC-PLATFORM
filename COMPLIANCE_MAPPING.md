# Compliance Mapping: SOC2 / ISO27001 Controls

Control Category



Requirement



Mapped to File/Resource



Description



Encryption at Rest



Data must be encrypted



modules/rds/main.tf (KMS keys for RDS/Secrets)



RDS storage encrypted with KMS; Secrets Manager uses KMS.



Least Privilege



Access limited to necessary permissions



modules/security/main.tf (IAM roles/SGs)



Granular IAM for ECS; SGs restrict traffic to ECS/RDS only.



Monitoring/Audit



Continuous logging and alerts



modules/ecs/main.tf (CloudWatch Dashboard); modules/vpc/main.tf (Flow Logs)



Dashboard monitors metrics; Flow Logs capture network traffic.



Availability



High availability and backups



modules/rds/main.tf (Multi-AZ, backups); modules/vpc/main.tf (3-AZ setup)



Multi-AZ RDS with 35-day retention; 3-AZ VPC ensures redundancy.



This mapping satisfies auditor requirements—reference these files during reviews.


