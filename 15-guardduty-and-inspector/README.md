# 15 — GuardDuty & Inspector

## Theory: Threat Detection vs. Vulnerability Management

These two services get confused constantly because they're both "security findings services," but they answer fundamentally different questions:

- **GuardDuty** asks "is something bad happening *right now*, based on behavior?" It's a threat detection service — it continuously analyzes CloudTrail management/data events, VPC Flow Logs (from [09](../09-vpc-security-deep-dive/README.md)), DNS query logs, and (with extensions) EKS/S3/RDS-specific signals, correlating them against threat intelligence feeds and anomaly-detection models. A finding looks like "this IAM credential just called the API from a Tor exit node it's never used before" or "this EC2 instance is querying a domain associated with a known cryptomining pool."
- **Inspector** asks "what's *vulnerable* about the things I've already deployed, independent of whether anyone's attacking it?" It's a vulnerability management service — it scans EC2 instances, container images in ECR, and Lambda functions against CVE databases and network-reachability analysis. A finding looks like "this EC2 instance is running an OpenSSL version with a known critical CVE" — regardless of whether anyone's exploited it yet.

Put simply: GuardDuty tells you about an active threat or suspicious behavior; Inspector tells you about a weakness that *could become* one. You want both — GuardDuty without Inspector means you might not notice the vulnerable software until it's already being exploited; Inspector without GuardDuty means you might patch everything on schedule but never notice if someone's already inside using stolen credentials rather than an unpatched CVE.

## Lab 15.1 — Enable GuardDuty, Review Sample Findings

```bash
# Enable GuardDuty in this region (this alone enables the core detector)
aws guardduty create-detector --enable

# Note the DetectorId from the output
aws guardduty list-detectors
```

GuardDuty needs time (hours to days) to build a baseline before its anomaly-based findings are meaningful, so for lab purposes generate **sample findings** — synthetic findings covering the full range of finding types, clearly labeled as samples, with no actual malicious activity involved:

```bash
aws guardduty create-sample-findings \
  --detector-id <DETECTOR_ID> \
  --finding-types Backdoor:EC2/C&CActivity.B!DNS UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B Recon:EC2/PortProbeUnprotectedPort

# List and review them
aws guardduty list-findings --detector-id <DETECTOR_ID>

aws guardduty get-findings \
  --detector-id <DETECTOR_ID> \
  --finding-ids <FINDING_ID_1> <FINDING_ID_2>
```

Each finding includes a **severity** (Low/Medium/High), a **finding type** encoding the category and resource (e.g., `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` — an anomalous console login), and a full detail record — source IP, geolocation, the specific API calls involved. Walking through a few sample findings of different types is worth the time: it's the fastest way to build intuition for what a real finding will look like months from now when you're not expecting one.

Wire GuardDuty findings into the SNS topic from Section 14 via EventBridge, so high-severity findings reach your inbox the same way root login does:

```bash
aws events put-rule \
  --name guardduty-high-severity \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": { "severity": [{ "numeric": [">=", 7] }] }
  }'

aws events put-targets \
  --rule guardduty-high-severity \
  --targets "Id"="1","Arn"="<SNS_TOPIC_ARN>"
```

## Lab 15.2 — Enable Inspector, Review Vulnerability/CVE Findings

```bash
# Enable Inspector for EC2 and ECR scanning in this account/region
aws inspector2 enable \
  --resource-types EC2 ECR

# Check activation status
aws inspector2 batch-get-account-status
```

Inspector automatically discovers and scans any running EC2 instance that has the **SSM agent** installed and registered — which every instance built through this repo already has, since [07](../07-ec2-bastion-ssm-patch-hygiene/README.md) set up the `EC2-SSM-Role`/`EC2-SSM-Profile` for SSM Session Manager access. No separate agent install is needed.

```bash
# List findings, filtered to your app instances
aws inspector2 list-findings \
  --filter-criteria '{
    "resourceType": [{ "comparison": "EQUALS", "value": "AWS_EC2_INSTANCE" }]
  }'

# Get full detail on a specific finding, including the CVE ID and fix availability
aws inspector2 batch-get-finding-details \
  --finding-arns <FINDING_ARN>
```

Findings are ranked by an Inspector-calculated severity score that factors in the CVSS base score **and** exploitability/network-reachability context — a critical CVE on a private-subnet instance with no inbound path (like the app instances from [06](../06-security-groups-and-nacls/README.md)) is scored lower than the same CVE on something internet-facing, since Inspector accounts for the fact that reachability matters as much as raw severity. This is exactly why Section 7's Patch Manager scan and this Inspector scan are complementary rather than redundant: Patch Manager applies fixes on the schedule *you* set, Inspector tells you continuously which of those unpatched gaps actually matter most given your network exposure.

---

**Previous:** [14 — CloudWatch & Alarms](../14-cloudwatch-and-alarms/README.md)
**Next:** [16 — Security Hub & Trusted Advisor](../16-security-hub-and-trusted-advisor/README.md)
