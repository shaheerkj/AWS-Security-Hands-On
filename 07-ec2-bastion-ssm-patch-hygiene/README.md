# 07 — EC2, Bastion/SSM & Patch Hygiene

## Theory: Reducing Attack Surface, and Why Bastions Are Increasingly Optional

The bastion pattern in Section 6 is a real, widely-used design — but it has a cost: it's a standing EC2 instance with an open SSH port, which is itself something to patch, monitor, and potentially compromise. AWS Systems Manager (**SSM**) **Session Manager** removes the need for it entirely: it gives you a shell into a private-subnet instance over the AWS API, using IAM for authorization, with no inbound port open at all — not even 22.

This matters because:

- No open SSH port means no brute-force surface, no bastion to patch, no SSH key management/rotation problem.
- Every session is logged to CloudTrail and can be logged to CloudWatch/S3, giving you a full audit trail of who ran what, when — something raw SSH doesn't give you for free.
- Access is controlled entirely by IAM policy, so revoking someone's access is an IAM change, not a key-rotation exercise.

**IMDSv2** (Instance Metadata Service v2) is a related hardening step: IMDSv1 lets *any* process on the instance — including one hijacked via SSRF in a web app — fetch the instance's IAM role credentials over HTTP with a simple GET request. IMDSv2 requires a session token obtained via a PUT request first, which most SSRF techniques can't perform, closing off a well-known class of credential-theft attack.

## Lab 7.1 — Connect via SSM Session Manager Instead of Opening SSH to the Internet

First, the instance needs an IAM role that lets the SSM agent talk to the SSM service:

```bash
# Trust policy allowing EC2 to assume this role
cat > ssm-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name EC2-SSM-Role \
  --assume-role-policy-document file://ssm-trust-policy.json

aws iam attach-role-policy \
  --role-name EC2-SSM-Role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

aws iam create-instance-profile --instance-profile-name EC2-SSM-Profile
aws iam add-role-to-instance-profile \
  --instance-profile-name EC2-SSM-Profile \
  --role-name EC2-SSM-Role
```

Launch (or relaunch) the app instance from Section 6 with this profile attached, and — critically — **no SSH ingress rule at all** in its Security Group:

```bash
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --subnet-id <PRIVATE_SUBNET_A_ID> \
  --security-group-ids <APP_SG_ID> \
  --iam-instance-profile Name=EC2-SSM-Profile \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=app-server-ssm}]'
```

The SSM agent talks *outbound* to the SSM service over HTTPS (443), so the instance needs the NAT Gateway path from Section 5 (or a VPC endpoint, covered in Section 9) — but nothing needs to reach *in*.

```bash
# Confirm the instance is registered with SSM (may take a minute after boot)
aws ssm describe-instance-information

# Start an interactive session — no SSH key, no open port 22
aws ssm start-session --target <INSTANCE_ID>
```

You now have a shell, and you never opened an inbound port. This is the pattern to prefer over the bastion from Section 6 wherever possible — keep the bastion pattern in your back pocket for scenarios SSM doesn't cover (e.g., protocols other than shell/port-forwarding), but default to SSM.

## Lab 7.2 — Patch Manager and (a preview of) Inspector Findings

```bash
# Run an on-demand patch scan against the instance, tagged for patching
aws ec2 create-tags \
  --resources <INSTANCE_ID> \
  --tags Key=Patch Group,Value=SecurityLabServers

aws ssm create-association \
  --name AWS-RunPatchBaseline \
  --targets "Key=tag:Patch Group,Values=SecurityLabServers" \
  --parameters '{"Operation":["Scan"]}' \
  --schedule-expression "rate(7 days)"

# Trigger an immediate scan rather than waiting for the schedule
aws ssm send-command \
  --document-name "AWS-RunPatchBaseline" \
  --parameters '{"Operation":["Scan"]}' \
  --targets "Key=tag:Patch Group,Values=SecurityLabServers"

# Check compliance status
aws ssm list-compliance-items \
  --resource-ids <INSTANCE_ID> \
  --resource-types ManagedInstance
```

Amazon **Inspector** goes further than Patch Manager — it continuously scans EC2 instances (and ECR images, Lambda functions) for known CVEs and network reachability issues, without you having to trigger anything. It's covered properly on Day 15 once you've enabled it at the account level; for now, know that Patch Manager fixes what you tell it to, while Inspector tells you what's vulnerable *before* you think to look.

## Lab 7.3 — Enforce IMDSv2

```bash
# Require IMDSv2 (token-based) on a running instance
aws ec2 modify-instance-metadata-options \
  --instance-id <INSTANCE_ID> \
  --http-tokens required \
  --http-endpoint enabled

# Enforce it by default for every future instance launch in the account/region
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

With `--http-tokens required`, a plain `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` (the classic IMDSv1 credential-theft one-liner) simply fails — the caller must first `PUT` to fetch a session token and pass it as a header, which most SSRF payloads can't do without being specifically written for it.

---

**Previous:** [06 — Security Groups & NACLs](../06-security-groups-and-nacls/README.md)
**Next:** [08 — Load Balancing & Auto Scaling](../08-load-balancing-and-auto-scaling/README.md)
