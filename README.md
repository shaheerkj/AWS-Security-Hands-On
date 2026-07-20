# AWS Security Foundations: IAM, From Zero to Audited

A self-directed, hands-on path through AWS Identity & Access Management —
the layer everything else (networking, encryption, incident response) sits on top of.

Each part below has its own folder with the IAM/JSON policy documents and the
equivalent AWS CLI commands, so you can run the labs directly.

## Structure

| Part | Folder | Covers |
|------|--------|--------|
| 1 | [`01-account-hardening-iam-basics`](./01-account-hardening-iam-basics) | Root vs IAM users, MFA, least-privilege policies, explicit vs default deny |
| 2 | [`02-iam-roles-federation-sts`](./02-iam-roles-federation-sts) | Roles vs users, STS temporary credentials, instance profiles, cross-account access, IAM Identity Center (SSO) |
| 3 | [`03-organizations-scps-billing-guardrails`](./03-organizations-scps-billing-guardrails) | AWS Organizations, Service Control Policies, budget alerts, Cost Explorer |
| 4 | [`04-cloudtrail-config`](./04-cloudtrail-config) | CloudTrail (who did what), AWS Config (configuration drift), Athena queries over logs |

Each part folder has:
- `policies/` — the raw JSON IAM/SCP/bucket policy documents
- `commands/` — the AWS CLI commands (or console steps, where CLI isn't possible) to run each lab, referencing the JSON files above

## Prerequisites

- An AWS account (Free Tier is enough for most labs)
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) installed and configured
- Replace all `<ACCOUNT_ID>`, `<ACCOUNT_A_ID>`, `<ACCOUNT_B_ID>`, and bucket names/keys with your own values before running
