# 03 — Organizations, SCPs & Billing Guardrails

## Theory: Guardrails vs. Granular IAM

IAM policies answer "what can this specific identity do?" — they're granular and per-account. **Service Control Policies (SCPs)**, available through **AWS Organizations**, answer a different question: "what is even *possible* in this account or OU, regardless of how permissive any IAM policy is?"

SCPs don't grant permissions — they set the **ceiling**. Even an account's root user cannot exceed what an SCP allows. This is why SCPs are called guardrails: they reduce the **blast radius** of a compromised credential or a careless admin, because no identity-based policy in that account can punch through them.

A common multi-account strategy: use Organizations to separate workloads (prod, dev, sandbox, security-tooling) into different accounts, each with its own IAM, but apply SCPs at the OU level to enforce org-wide rules — e.g., "no account outside the `networking` OU can create a VPC peering connection," or "no account may disable CloudTrail."

## Lab 3.1 — Explore Organizations and SCPs

```bash
# View your organization structure (requires being in the management account)
aws organizations describe-organization

aws organizations list-roots

aws organizations list-accounts
```

Example SCP that blocks disabling CloudTrail anywhere in an OU — this is a classic guardrail. Save as `deny-cloudtrail-scp.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudTrailDisable",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail"
      ],
      "Resource": "*"
    }
  ]
}
```

```bash
aws organizations create-policy \
  --name DenyCloudTrailTampering \
  --type SERVICE_CONTROL_POLICY \
  --content file://deny-cloudtrail-scp.json

aws organizations attach-policy \
  --policy-id <policy-id-from-output> \
  --target-id <ou-or-account-id>
```

If you only have a single account, you can still read the SCP docs and reason through examples — Organizations becomes essential the moment you split workloads across accounts, which is worth planning for even as a solo learner.

## Lab 3.2 — Budget Alert

```bash
aws budgets create-budget \
  --account-id <ACCOUNT_ID> \
  --budget '{
    "BudgetName": "MonthlyGuardrail",
    "BudgetLimit": { "Amount": "5", "Unit": "USD" },
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST"
  }' \
  --notifications-with-subscribers '[
    {
      "Notification": {
        "NotificationType": "ACTUAL",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 80,
        "ThresholdType": "PERCENTAGE"
      },
      "Subscribers": [
        { "SubscriptionType": "EMAIL", "Address": "you@example.com" }
      ]
    }
  ]'
```

This emails you when actual spend crosses 80% of a $5 monthly budget — cheap insurance against a forgotten resource racking up charges.

## Lab 3.3 — Cost Explorer Review

Cost Explorer is console-only for exploration, but you can pull the same data via CLI:

```bash
aws ce get-cost-and-usage \
  --time-period Start=2026-06-01,End=2026-07-01 \
  --granularity MONTHLY \
  --metrics "UnblendedCost" \
  --group-by Type=DIMENSION,Key=SERVICE
```

Review this monthly. It's not just a cost exercise — an unexpected service appearing in the breakdown (e.g., EC2 spend in a region you don't use) is often the first sign of compromised credentials being used for cryptomining.

---

**Previous:** [02 — IAM Roles, Federation & STS](../02-iam-roles-federation-sts/README.md)
**Next:** [04 — CloudTrail & Config](../04-cloudtrail-config/README.md)
