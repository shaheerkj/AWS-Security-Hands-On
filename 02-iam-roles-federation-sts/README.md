# 02 — IAM Roles, Federation & STS

## Theory: Roles vs. Users, and Why Long-Lived Keys Are a Risk

An IAM **user** has permanent credentials (password, access keys) tied to a specific identity. An IAM **role** has no credentials of its own — instead, it defines a **trust policy** stating *who* is allowed to assume it, and a permissions policy stating *what* they can do once they have.

When something assumes a role, AWS's **Security Token Service (STS)** hands back **temporary credentials**: an access key, secret key, and session token, valid for anywhere from 15 minutes to 12 hours.

Why this matters for security:

- **Long-lived access keys** embedded in code, AMIs, or config files are a top cause of real-world breaches — they get committed to git repos, baked into containers, or leaked in logs, and they work until someone manually rotates or revokes them.
- **Temporary credentials** expire automatically. Even if leaked, the blast radius is bounded by time.
- Roles also make **cross-account access** and **federation** (letting external identity providers like Okta, Google Workspace, or corporate AD authenticate into AWS) possible without ever creating IAM users for every external identity.

## Lab 2.1 — EC2 Instance Profile Instead of Embedded Keys

Never put access keys in an EC2 instance's user data or config files. Instead, attach a role via an **instance profile**.

Trust policy — save as `ec2-trust-policy.json` — this says "EC2 is allowed to assume this role":

```json
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
```

```bash
# Create the role
aws iam create-role \
  --role-name EC2-S3ReadOnly \
  --assume-role-policy-document file://ec2-trust-policy.json

# Attach a permissions policy (AWS managed, for simplicity)
aws iam attach-role-policy \
  --role-name EC2-S3ReadOnly \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Create an instance profile and add the role to it
aws iam create-instance-profile --instance-profile-name EC2-S3ReadOnly-Profile
aws iam add-role-to-instance-profile \
  --instance-profile-name EC2-S3ReadOnly-Profile \
  --role-name EC2-S3ReadOnly

# Launch an instance with the profile attached
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --iam-instance-profile Name=EC2-S3ReadOnly-Profile \
  --key-name my-keypair
```

From inside the instance, the AWS SDK/CLI automatically picks up temporary credentials from the instance metadata service — no keys anywhere in your code.

## Lab 2.2 — Cross-Account AssumeRole via STS

Say you have Account A (source) and Account B (target). You want a user in Account A to assume a role in Account B.

**In Account B**, create a role that trusts Account A. Save as `cross-account-trust.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_A_ID>:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:ExternalId": "shared-secret-value" }
      }
    }
  ]
}
```

```bash
# Run in Account B
aws iam create-role \
  --role-name CrossAccountReadOnly \
  --assume-role-policy-document file://cross-account-trust.json

aws iam attach-role-policy \
  --role-name CrossAccountReadOnly \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

**In Account A**, assume the role:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_B_ID>:role/CrossAccountReadOnly \
  --role-session-name my-session \
  --external-id shared-secret-value
```

This returns a JSON blob with `AccessKeyId`, `SecretAccessKey`, and `SessionToken`. Export them as environment variables to act as that role:

```bash
export AWS_ACCESS_KEY_ID=<from output>
export AWS_SECRET_ACCESS_KEY=<from output>
export AWS_SESSION_TOKEN=<from output>

aws sts get-caller-identity   # confirms you're now Account B's role
```

The `ExternalId` condition is a defense against the **confused deputy problem** — it stops a third party from tricking Account B's role into being assumed by someone who merely knows the role ARN.

## Lab 2.3 — IAM Identity Center (SSO) Permission Set

If your region/org supports it (IAM Identity Center is org-wide, not per-account):

1. **IAM Identity Center** → Enable.
2. **Permission sets** → Create permission set → choose a predefined policy like `ReadOnlyAccess` or build a custom one.
3. **AWS accounts** → assign the permission set to your account and to a user/group.
4. Users then log in via the **Identity Center portal URL** and get temporary, role-based access — no IAM users, no long-lived keys, one login for multiple accounts.

This is the direction AWS pushes larger organizations: centralize identity, federate everywhere, stop creating IAM users per account entirely.

---

**Previous:** [01 — Account Hardening & IAM Basics](../01-account-hardening-iam-basics/README.md)
**Next:** [03 — Organizations, SCPs & Billing Guardrails](../03-organizations-scps-billing-guardrails/README.md)
