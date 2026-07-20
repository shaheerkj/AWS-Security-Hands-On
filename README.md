# AWS Security Foundations: Identity & Access Management, From Zero to Audited

If you're starting a self-directed AWS security journey, everything else you'll ever do — network segmentation, encryption, incident response — sits on top of one thing: **identity**. Get IAM wrong and every other control you build is decoration on a house with no foundation.

This repo walks through four building blocks, each with theory and hands-on labs you can run today, mostly inside the AWS Free Tier.

## Contents

| # | Topic | Description |
|---|-------|-------------|
| [01](./01-account-hardening-iam-basics/README.md) | Account Hardening & IAM Basics | Root vs. IAM users, least privilege, explicit vs. default deny |
| [02](./02-iam-roles-federation-sts/README.md) | IAM Roles, Federation & STS | Roles vs. users, temporary credentials, cross-account access, SSO |
| [03](./03-organizations-scps-billing-guardrails/README.md) | Organizations, SCPs & Billing Guardrails | Org-wide permission ceilings, budget alerts, cost review |
| [04](./04-cloudtrail-config/README.md) | CloudTrail & Config | Detective controls, audit logging, continuous compliance |


## Prerequisites

- An AWS account (Free Tier is sufficient for these labs)
- AWS CLI v2 installed and configured
- Basic comfort with the command line and JSON

