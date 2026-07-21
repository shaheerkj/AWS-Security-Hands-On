# AWS Security Foundations: From Zero to Audited

A self-directed, 20-day, hands-on AWS security curriculum — from locking down a brand-new account through building and tearing down a fully monitored, encrypted, least-privilege 3-tier architecture. Every section pairs theory with runnable AWS CLI (and, where relevant, CloudFormation/Terraform) labs, mostly inside the AWS Free Tier.

Work through the phases in order — each one builds directly on resources, roles, and concepts created in the last.

## Contents

### Phase 1: Identity & Access Management

| # | Topic | Description |
|---|-------|-------------|
| [01](./01-account-hardening-iam-basics/README.md) | Account Hardening & IAM Basics | Root vs. IAM users, least privilege, explicit vs. default deny |
| [02](./02-iam-roles-federation-sts/README.md) | IAM Roles, Federation & STS | Roles vs. users, temporary credentials, cross-account access, SSO |
| [03](./03-organizations-scps-billing-guardrails/README.md) | Organizations, SCPs & Billing Guardrails | Org-wide permission ceilings, budget alerts, cost review |
| [04](./04-cloudtrail-config/README.md) | CloudTrail & Config | Detective controls, audit logging, continuous compliance |

### Phase 2: Networking & Compute

| # | Topic | Description |
|---|-------|-------------|
| [05](./05-vpc-fundamentals/README.md) | VPC Fundamentals | Custom VPC, public/private subnets across AZs, IGW, NAT Gateway |
| [06](./06-security-groups-and-nacls/README.md) | Security Groups & NACLs | Stateful vs. stateless filtering, bastion access, defense in depth |
| [07](./07-ec2-bastion-ssm-patch-hygiene/README.md) | EC2, Bastion/SSM & Patch Hygiene | SSM Session Manager, Patch Manager, Inspector, IMDSv2 |
| [08](./08-load-balancing-and-auto-scaling/README.md) | Load Balancing & Auto Scaling | ALB + ASG across AZs, ACM/TLS termination, HTTPS redirect |
| [09](./09-vpc-security-deep-dive/README.md) | VPC Security Deep Dive | Flow Logs, VPC Endpoints, Transit Gateway/Peering concepts |

### Phase 3: Storage, Data & Encryption

| # | Topic | Description |
|---|-------|-------------|
| [10](./10-s3-fundamentals-and-public-access/README.md) | S3 Fundamentals & Public Access | Block Public Access, bucket policies, versioning, lifecycle rules |
| [11](./11-encryption-and-kms/README.md) | Encryption & KMS | Customer Managed Keys, key policies, SSE-S3 vs SSE-KMS |
| [12](./12-secrets-and-credential-management/README.md) | Secrets & Credential Management | Secrets Manager, Parameter Store, rotation, no hardcoded creds |
| [13](./13-databases-and-rds-security/README.md) | Databases & RDS Security | Private-subnet RDS, DB-tier SGs, encryption at rest, backups |

### Phase 4: Detection, Monitoring & Threat Response

| # | Topic | Description |
|---|-------|-------------|
| [14](./14-cloudwatch-and-alarms/README.md) | CloudWatch & Alarms | Metrics vs. logs vs. events, CloudTrail metric filters, SNS alerting |
| [15](./15-guardduty-and-inspector/README.md) | GuardDuty & Inspector | Threat detection vs. vulnerability management, sample findings |
| [16](./16-security-hub-and-trusted-advisor/README.md) | Security Hub & Trusted Advisor | Centralized CSPM, CIS Benchmark, Trusted Advisor security checks |
| [17](./17-waf-shield-and-incident-response-basics/README.md) | WAF, Shield & Incident Response Basics | App-layer protection, DDoS mitigation, IR runbook basics |

### Phase 5: Serverless, IaC & Capstone

| # | Topic | Description |
|---|-------|-------------|
| [18](./18-serverless-and-least-privilege-functions/README.md) | Serverless & Least-Privilege Functions | Scoped Lambda execution roles, API Gateway auth, event-driven security |
| [19](./19-infrastructure-as-code/README.md) | Infrastructure as Code | CloudFormation/Terraform, shift-left scanning, drift detection |
| [20](./20-capstone-secure-3tier-architecture-review/README.md) | Capstone: Secure 3-Tier Architecture Review | Full build, threat model, and teardown tying every prior topic together |

## What you'll have by the end

- Root locked down, MFA everywhere, least-privilege IAM users, roles, and Lambda execution policies
- A working mental model of explicit deny vs. default deny, and stateful vs. stateless filtering
- Temporary credentials (STS, roles) replacing embedded long-lived keys everywhere, including cross-account and serverless access
- Org-level guardrails (SCPs) and billing alarms that cap both permissions and spend
- A fully private, segmented network: public/private subnets, chained security groups, no open SSH, IMDSv2 enforced
- Encryption at rest and in transit by default, with a Customer Managed KMS key and proper key-policy separation of duties
- Secrets out of code entirely, via Secrets Manager / Parameter Store with rotation
- Full audit trail via CloudTrail, continuous compliance via Config, and centralized posture management via Security Hub
- Layered detection: GuardDuty (behavioral threats), Inspector (vulnerabilities), CloudWatch alarms (proactive alerting)
- Application-layer protection via WAF, and a practiced isolate → revoke → investigate → remediate incident response runbook
- Infrastructure defined as code, scanned before deploy, with drift detection in place
- A complete, working secure 3-tier reference architecture — built, threat-modeled, and cleanly torn down to $0

This is the identity, network, data, detection, and automation foundation that real-world AWS security work is built on.

## Prerequisites

- An AWS account (Free Tier is sufficient for most labs; a few — NAT Gateway, RDS, Shield Advanced discussion — incur small charges, called out where relevant)
- AWS CLI v2 installed and configured
- Basic comfort with the command line and JSON/YAML
- For Day 19: Terraform and/or the AWS CLI's CloudFormation support, plus `cfn-lint`/`checkov`/`tfsec` (installed within that section's lab)


