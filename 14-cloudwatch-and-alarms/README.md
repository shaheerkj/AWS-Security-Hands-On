# 14 — CloudWatch & Alarms

## Theory: Metrics vs. Logs vs. Events, and Proactive Alerting

CloudWatch is really three related but distinct systems, and knowing which one to reach for matters:

- **Metrics** are numeric time-series data — CPU utilization, request count, error rate. They're what you graph and what you set **alarms** on. Most AWS services publish metrics automatically; you can also publish custom metrics from your own application.
- **Logs** are the actual text output of a system — application logs, and (relevant here) **CloudTrail** logs once they're delivered into CloudWatch Logs. You can run **metric filters** over log data, which turn a pattern match in log text into a numeric metric you can then alarm on — this is the bridge between "an event happened" (a log line) and "someone gets paged" (an alarm).
- **Events** (EventBridge, formerly CloudWatch Events) react to state changes and API calls in near-real-time — "an EC2 instance just terminated," "a specific API call just happened" — and route them to a target (Lambda, SNS, etc.) without needing a log or a metric threshold at all.

This section focuses on the metrics + logs + alarm path, because it's the most direct route from "root user logged in" (a log line in CloudTrail) to "you get an email in under a minute" (an SNS notification) — which is the single highest-value alert most AWS accounts can set up. **Proactive alerting** means you find out about a suspicious event from an email, not from noticing unexpected charges or a support ticket three weeks later.

## Lab 14.1 — CloudWatch Alarm for CPU

```bash
# Basic CPU alarm on an EC2 instance from the ASG in Section 8
aws cloudwatch put-metric-alarm \
  --alarm-name high-cpu-app-instance \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=AutoScalingGroupName,Value=app-asg \
  --alarm-description "Alert when average CPU exceeds 80% for 10 minutes"
```

`--evaluation-periods 2` with a `--period 300` (5 minutes) means the alarm only fires after **two consecutive** 5-minute windows above threshold — this avoids false alarms from a brief, harmless spike, while still catching a genuine sustained problem quickly.

## Lab 14.2 — Custom Metric Filter on CloudTrail Logs: Root Login / AuthorizationFailure

This assumes CloudTrail is already delivering to CloudWatch Logs — if you only set up S3 delivery in [04](../04-cloudtrail-config/README.md), add a CloudWatch Logs destination first:

```bash
# IAM role letting CloudTrail write to CloudWatch Logs
cat > cloudtrail-cwl-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name CloudTrail-CWL-Role \
  --assume-role-policy-document file://cloudtrail-cwl-trust-policy.json

aws logs create-log-group --log-group-name /cloudtrail/org-wide-trail

aws cloudtrail update-trail \
  --name org-wide-trail \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:<ACCOUNT_ID>:log-group:/cloudtrail/org-wide-trail:* \
  --cloud-watch-logs-role-arn arn:aws:iam::<ACCOUNT_ID>:role/CloudTrail-CWL-Role
```

Create a metric filter that matches root user activity — a pattern searching CloudTrail's JSON log structure for `userIdentity.type = "Root"`, excluding routine AWS-service-initiated events:

```bash
aws logs put-metric-filter \
  --log-group-name /cloudtrail/org-wide-trail \
  --filter-name RootAccountUsage \
  --filter-pattern '{ ($.userIdentity.type = "Root") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != "AwsServiceEvent") }' \
  --metric-transformations \
      metricName=RootAccountUsageCount,metricNamespace=SecurityMetrics,metricValue=1,defaultValue=0
```

Create a second filter for `AuthorizationFailure` — repeated failures are a signal of either a misconfigured app or someone probing what a stolen credential can do:

```bash
aws logs put-metric-filter \
  --log-group-name /cloudtrail/org-wide-trail \
  --filter-name AuthorizationFailures \
  --filter-pattern '{ ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }' \
  --metric-transformations \
      metricName=AuthFailureCount,metricNamespace=SecurityMetrics,metricValue=1,defaultValue=0
```

## Lab 14.3 — Route the Alarm to SNS → Email

```bash
# Create the SNS topic and subscribe your email
aws sns create-topic --name security-alerts

aws sns subscribe \
  --topic-arn <TOPIC_ARN> \
  --protocol email \
  --notification-endpoint you@example.com
# Check your inbox and confirm the subscription — SNS won't deliver until you do
```

Create alarms on the two metric filters, both pointing at the SNS topic:

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name root-account-usage-alarm \
  --metric-name RootAccountUsageCount \
  --namespace SecurityMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions <TOPIC_ARN> \
  --treat-missing-data notBreaching \
  --alarm-description "Fires immediately on ANY root account activity"

aws cloudwatch put-metric-alarm \
  --alarm-name auth-failure-spike-alarm \
  --metric-name AuthFailureCount \
  --namespace SecurityMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions <TOPIC_ARN> \
  --treat-missing-data notBreaching \
  --alarm-description "Fires when 5+ AccessDenied/UnauthorizedAccess events occur in 5 minutes"
```

The root-usage alarm deliberately has `--threshold 1` and `--evaluation-periods 1` — unlike the CPU alarm, there's no legitimate reason for *any* delay here. Root login should be rare enough (per [01](../01-account-hardening-iam-basics/README.md)'s guidance) that a single occurrence is worth an immediate email, not a pattern you wait to confirm.

Test the wiring end-to-end by logging in as root once (you'll have re-enabled root MFA login in Section 1) and confirming the email arrives within a few minutes — CloudTrail delivery to CloudWatch Logs typically lags by 2–5 minutes, which is worth knowing so you don't assume the alarm is broken when it's just catching up.

---

**Previous:** [13 — Databases & RDS Security](../13-databases-and-rds-security/README.md)
**Next:** [15 — GuardDuty & Inspector](../15-guardduty-and-inspector/README.md)
