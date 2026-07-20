# 04 — CloudTrail & Config

## Theory: Detective Controls and Configuration Drift

Everything in the previous sections is **preventive** — stopping bad things from happening. CloudTrail and Config are **detective controls** — telling you what *did* happen, so you can investigate and respond.

- **CloudTrail** logs every API call made in your account: who made it, from where, when, and what the result was. This is your forensic trail for "who deleted that S3 bucket at 3am."
- **AWS Config** continuously records the *configuration state* of your resources and can evaluate them against rules. This catches **configuration drift** — when a resource silently moves out of compliance (e.g., someone flips an S3 bucket to public) — even if no alarm was watching for that specific action.

Together they form the backbone of **compliance-as-code**: instead of manually auditing your account, you encode the rules ("MFA must be enabled," "no public S3 buckets") and let AWS continuously check them.

## Lab 4.1 — Multi-Region CloudTrail with Log File Validation

```bash
# Create an S3 bucket to hold logs (bucket names must be globally unique)
aws s3api create-bucket \
  --bucket my-cloudtrail-logs-2026 \
  --region us-east-1

# Attach a bucket policy allowing CloudTrail to write to it
cat > cloudtrail-bucket-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::my-cloudtrail-logs-2026"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-cloudtrail-logs-2026/AWSLogs/<ACCOUNT_ID>/*",
      "Condition": {
        "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" }
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket my-cloudtrail-logs-2026 \
  --policy file://cloudtrail-bucket-policy.json

# Create the trail: multi-region, with log file validation (tamper detection)
aws cloudtrail create-trail \
  --name org-wide-trail \
  --s3-bucket-name my-cloudtrail-logs-2026 \
  --is-multi-region-trail \
  --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name org-wide-trail
```

**Log file validation** works by hashing each delivered log file and chaining the hashes together, so any tampering with a historical log file (even by someone with S3 access) is mathematically detectable.

## Lab 4.2 — Querying "Who Deleted/Created What"

Quick lookups via **Event History** (last 90 days, no setup needed):

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteBucket \
  --max-results 10
```

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=jdoe-admin \
  --start-time 2026-07-01T00:00:00Z \
  --end-time 2026-07-20T00:00:00Z
```

For longer retention and complex queries (joins, aggregations across months of logs), use **Athena** against the S3 bucket:

```sql
CREATE EXTERNAL TABLE cloudtrail_logs (
  eventVersion STRING,
  userIdentity STRUCT
    type: STRING,
    arn: STRING,
    userName: STRING
  >,
  eventTime STRING,
  eventName STRING,
  eventSource STRING,
  awsRegion STRING,
  sourceIPAddress STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://my-cloudtrail-logs-2026/AWSLogs/<ACCOUNT_ID>/CloudTrail/';
```

```sql
SELECT eventTime, userIdentity.userName, eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN ('DeleteBucket', 'DeleteUser', 'DeleteRole')
ORDER BY eventTime DESC
LIMIT 20;
```

## Lab 4.3 — AWS Config Rules

```bash
# Create a configuration recorder (records resource state changes)
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::<ACCOUNT_ID>:role/aws-config-role \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

# Create a delivery channel (where snapshots/history go)
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=my-config-logs-2026

# Start recording
aws configservice start-configuration-recorder --configuration-recorder-name default

# Add a managed rule: flag IAM users without MFA
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "iam-user-mfa-enabled",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "IAM_USER_MFA_ENABLED"
    }
  }'

# Add a managed rule: flag public S3 buckets
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    }
  }'
```

Check compliance status any time:

```bash
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited
```

Config will now continuously evaluate every matching resource and flag drift the moment it happens — not just when you remember to check.

---

**Previous:** [03 — Organizations, SCPs & Billing Guardrails](../03-organizations-scps-billing-guardrails/README.md)

