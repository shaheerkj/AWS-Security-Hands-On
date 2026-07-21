# 17 — WAF, Shield & Incident Response Basics

## Theory: Application-Layer Protection, DDoS Mitigation, and IR Runbook Basics

Everything through Section 16 is about *detecting* problems. This closing section adds one more preventive layer at the application edge, then walks through what to actually *do* when detection surfaces a real incident.

**AWS WAF (Web Application Firewall)** attaches to the ALB (from [08](../08-load-balancing-and-auto-scaling/README.md)) and inspects HTTP requests *before* they reach your application, matching them against rules — either ones you write, or **AWS Managed Rule Groups** maintained by AWS covering common attack patterns like SQL injection and cross-site scripting (XSS). This is **application-layer (L7) protection**: it understands HTTP structure, unlike an SG/NACL which only sees IP/port/protocol.

**AWS Shield** is DDoS protection, and comes in two tiers: **Shield Standard** is automatic, free, and applied to every AWS account by default — it protects against the most common network/transport-layer (L3/L4) DDoS patterns with no setup. **Shield Advanced** is a paid, opt-in service adding L7 DDoS protection, near-real-time attack visibility, DDoS cost protection (credits if a DDoS event inflates your bill), and access to the AWS DDoS Response Team (DRT) — the kind of thing that makes sense for an internet-facing production service where downtime has real cost, not something every account needs by default.

An **incident response (IR) runbook** is the pre-agreed sequence of steps you follow the moment you suspect a compromise, so you're executing a checklist under pressure rather than improvising. The canonical order — **isolate → revoke → investigate → remediate** — matters because it's ordered by urgency-to-blast-radius ratio: isolating and revoking are fast, reversible-if-wrong, and stop active damage immediately; investigation and remediation take longer and should happen once the bleeding has stopped, not before.

## Lab 17.1 — Attach WAF to the ALB, Add a Managed Rule Group, Test It

```bash
# Create a Web ACL with the SQL injection and common-attack managed rule groups
aws wafv2 create-web-acl \
  --name app-web-acl \
  --scope REGIONAL \
  --default-action Allow={} \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=app-web-acl \
  --rules '[
    {
      "Name": "AWS-AWSManagedRulesSQLiRuleSet",
      "Priority": 1,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesSQLiRuleSet"
        }
      },
      "OverrideAction": { "None": {} },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "SQLiRuleSet"
      }
    },
    {
      "Name": "AWS-AWSManagedRulesCommonRuleSet",
      "Priority": 2,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesCommonRuleSet"
        }
      },
      "OverrideAction": { "None": {} },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "CommonRuleSet"
      }
    }
  ]'
```

`AWSManagedRulesCommonRuleSet` covers a broad baseline including XSS patterns; `AWSManagedRulesSQLiRuleSet` is specifically tuned for SQL injection. Attach the Web ACL to the ALB from Section 8:

```bash
aws wafv2 associate-web-acl \
  --web-acl-arn <WEB_ACL_ARN> \
  --resource-arn <ALB_ARN>
```

Test it with a request carrying an obvious SQLi pattern — this should now be blocked at the WAF layer, returning a `403` before it ever reaches the app instances:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://app.example.com/search?q=' OR '1'='1"
# expect: 403

# A normal request should still pass through untouched
curl -s -o /dev/null -w "%{http_code}\n" "https://app.example.com/"
# expect: 200 (or whatever your health endpoint returns)
```

Check the sampled requests to see exactly which rule matched:

```bash
aws wafv2 get-sampled-requests \
  --web-acl-arn <WEB_ACL_ARN> \
  --rule-metric-name SQLiRuleSet \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -d '10 minutes ago' +%s),EndTime=$(date -u +%s) \
  --max-items 10
```

## Lab 17.2 — Shield Standard vs. Shield Advanced

No setup needed for Shield Standard — confirm it's active (it always is, for every account):

```bash
aws shield describe-subscription 2>&1 || echo "Not subscribed to Shield Advanced (Standard protection is still active automatically)"
```

Shield Standard already covers the ALB and any Elastic IPs in this repo's architecture against common L3/L4 flood attacks, with no action required. Shield Advanced is a per-account subscription (roughly $3,000/month at time of writing, plus data transfer commitments) — worth reading about, not worth enabling for this lab:

```bash
# Read-only: what Shield Advanced would add, without subscribing
aws shield describe-drt-access 2>&1 || true
```

The practical takeaway: Shield Standard + WAF (Lab 17.1) + the ALB health checks and multi-AZ ASG from [08](../08-load-balancing-and-auto-scaling/README.md) together cover the large majority of what a small-to-mid-size workload needs. Shield Advanced becomes worth its cost specifically when downtime has a large, quantifiable business cost and you need guaranteed response-team engagement during an active attack — a decision, not a default.

## Lab 17.3 — Simulate an Incident: Revoke, Rotate, Investigate

Scenario: you suspect an IAM access key has been compromised (leaked in a public repo, found in a log, whatever the trigger). Walk the **isolate → revoke → investigate → remediate** sequence for real.

**Isolate/Revoke — first, immediately, before anything else:**

```bash
# Find the key in question
aws iam list-access-keys --user-name jdoe-admin

# Deactivate it immediately — this is reversible and near-instant, do this FIRST
aws iam update-access-key \
  --user-name jdoe-admin \
  --access-key-id <ACCESS_KEY_ID> \
  --status Inactive
```

Deactivating (not yet deleting) is deliberate: it stops the key from working *immediately* while preserving it for the investigation step below. Deleting destroys the evidence trail of which key it was.

**Investigate — now that the bleeding has stopped, look at what happened:**

```bash
# Full history of everything this key did, most recent first
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<ACCESS_KEY_ID> \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50

# Cross-check against GuardDuty in case it already flagged this key's behavior
aws guardduty list-findings \
  --detector-id <DETECTOR_ID> \
  --finding-criteria '{
    "Criterion": {
      "resource.accessKeyDetails.accessKeyId": { "Eq": ["<ACCESS_KEY_ID>"] }
    }
  }'
```

Look specifically for anything unexpected: API calls from unfamiliar IPs/regions, IAM changes (new users, new access keys, policy attachments — signs of privilege escalation or persistence), or resource creation in unused regions (classic cryptomining pattern, the same thing Lab 3.3's Cost Explorer review is designed to catch after the fact).

**Remediate — once you understand the scope:**

```bash
# Issue a brand-new key for legitimate ongoing use
aws iam create-access-key --user-name jdoe-admin

# Once the new key is confirmed working and distributed, delete the old one permanently
aws iam delete-access-key \
  --user-name jdoe-admin \
  --access-key-id <OLD_ACCESS_KEY_ID>

# If investigation revealed the key was used to create anything unauthorized, clean it up
# (example: an unexpected IAM user created for persistence)
aws iam list-users --query 'Users[?CreateDate>=`2026-07-15`]'
```

Deleting the old key only *after* confirming the new one works and only *after* the CloudTrail review is complete follows the same principle as the deactivate-don't-delete step above — do the reversible, safe thing first, do the destructive/final thing last, once you're confident you have the full picture. This four-step order — **isolate, revoke, investigate, remediate** — is the same shape you'd apply to any credential or resource compromise, not just an IAM key: stop it, cut its access, understand it, then clean up.

---

**Previous:** [16 — Security Hub & Trusted Advisor](../16-security-hub-and-trusted-advisor/README.md)

