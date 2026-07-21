# 16 — Security Hub & Trusted Advisor

## Theory: Centralized Security Posture Management and Compliance Frameworks

Every prior lab in this repo has produced findings or state living in its own service: GuardDuty findings live in GuardDuty, Inspector findings live in Inspector, Config compliance results (from [04](../04-cloudtrail-config/README.md)) live in Config. **AWS Security Hub** is a **CSPM (Cloud Security Posture Management)** layer that sits above all of them — it ingests findings from GuardDuty, Inspector, Config, IAM Access Analyzer (from [10](../10-s3-fundamentals-and-public-access/README.md)), and dozens of third-party tools, normalizes them into a common finding format (**AWS Security Finding Format**, ASFF), and gives you one dashboard and one severity-ranked queue to work from instead of five separate consoles.

Security Hub also runs its own **automated checks** against **compliance frameworks** — most notably the **CIS AWS Foundations Benchmark**, an industry-standard set of security configuration baselines (MFA on root, no wildcard IAM policies, CloudTrail enabled in all regions, and so on — many of which you've already satisfied by working through this repo in order). A compliance framework isn't a law — it's a checklist maintained by a standards body (CIS) or built into AWS's own recommendations, and Security Hub continuously re-evaluates your account against it, showing pass/fail per control alongside an overall score.

**Trusted Advisor** predates Security Hub and takes a different angle — it inspects your account against AWS best-practice checks across five categories (cost optimization, performance, resilience, service limits, and **security**), with a mix of checks available on every support plan and a larger set requiring **Business or Enterprise support**. Its security checks overlap partially with Security Hub/CIS (e.g., "is MFA enabled on root," "are any S3 buckets publicly readable") but it's a lighter-weight, no-setup-required view — useful as a quick sanity check even before you've enabled Security Hub at all.

## Lab 16.1 — Enable Security Hub, Aggregate Findings Against CIS

```bash
# Enable Security Hub — this alone starts ingesting findings from already-enabled services
aws securityhub enable-security-hub \
  --enable-default-standards
```

`--enable-default-standards` turns on the **AWS Foundational Security Best Practices** standard automatically; enable the CIS Benchmark explicitly as well:

```bash
# List available standards to get the CIS ARN for your region
aws securityhub describe-standards

# Subscribe to the CIS AWS Foundations Benchmark (v1.4.0 or latest available)
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {
      "StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
    }
  ]'
```

Give it a few minutes to run its initial evaluation pass, then check your score and pull the findings:

```bash
# Overall compliance summary
aws securityhub get-findings \
  --filters '{
    "ComplianceStatus": [{ "Value": "FAILED", "Comparison": "EQUALS" }],
    "RecordState": [{ "Value": "ACTIVE", "Comparison": "EQUALS" }]
  }' \
  --max-results 25
```

Findings are labeled with the specific CIS control they map to (e.g., `1.4 — Ensure no root account access key exists`, `2.1 — Ensure CloudTrail is enabled in all regions`) — if you've worked through Topics 1 and 2 in order, most of the identity and logging controls should already show as passing, which is a good concrete check that the earlier labs actually did what they claimed. Any `FAILED` results are your prioritized to-do list; Security Hub is designed so you work the queue rather than hunting for problems yourself.

Route Security Hub's own findings into the same SNS pipeline from Section 14, so new critical/high findings reach your inbox without you having to check the dashboard daily:

```bash
aws events put-rule \
  --name securityhub-critical-high \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Severity": { "Label": ["CRITICAL", "HIGH"] },
        "RecordState": ["ACTIVE"]
      }
    }
  }'

aws events put-targets \
  --rule securityhub-critical-high \
  --targets "Id"="1","Arn"="<SNS_TOPIC_ARN>"
```

## Lab 16.2 — Walk Through Trusted Advisor's Security Checks

Trusted Advisor's fuller check set is console-driven and support-plan-gated, but the core security checks are queryable via API on any plan through the newer Trusted Advisor API:

```bash
# List all Trusted Advisor checks available to your account
aws support describe-trusted-advisor-checks --language en

# Filter for security-category checks in the output, then pull results for one
aws support describe-trusted-advisor-check-result \
  --check-id <CHECK_ID>
```

Note: `aws support` API calls require **Business, Enterprise On-Ramp, or Enterprise support** — on Basic/Developer support, use the **Trusted Advisor console** instead (Support Center → Trusted Advisor → Security category), which shows a smaller free set of checks (S3 bucket permissions, security group unrestricted ports, IAM use, MFA on root, CloudTrail logging) without requiring a paid plan.

Walk through each security check present on your plan and compare its verdict against what you already know from Security Hub/CIS above — where they overlap (root MFA, public S3 buckets, CloudTrail), they should agree, and if they don't, that's worth a closer look; a disagreement between two independent checkers is a good signal something is worth verifying by hand.

---

**Previous:** [15 — GuardDuty & Inspector](../15-guardduty-and-inspector/README.md)
**Next:** [17 — WAF, Shield & Incident Response Basics](../17-waf-shield-and-incident-response-basics/README.md)
