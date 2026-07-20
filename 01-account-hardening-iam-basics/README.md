# 01 — Account Hardening & IAM Basics

## Theory: Root vs. IAM User

Every AWS account has a **root user** — the identity created when you sign up, tied to the account's email address. Root has *unconditional* access to everything, including actions no policy can restrict (closing the account, changing support plans, viewing certain billing data). Because it can't be meaningfully constrained, root should be locked away and never used for daily work.

**IAM users** are the identities you actually want to operate as. Their permissions come entirely from attached policies, which means you can scope them tightly.

Two policy families matter here:

- **Identity-based policies** — attached to a user, group, or role. They answer "what can *this identity* do?"
- **Resource-based policies** — attached to a resource (like an S3 bucket policy or KMS key policy). They answer "who can act on *this resource*?"

The **principle of least privilege** means granting only the permissions required for a task, nothing more. It's not a one-time setting — it's a discipline you revisit as roles change.

## Lab 1.1 — Enable MFA on Root, Stop Using It Daily

This is console-only (root MFA can't be scripted via CLI, by design):

1. Sign in as root → **IAM** → **Dashboard** → "Add MFA" under Security Recommendations.
2. Choose a virtual MFA device (e.g., Authy, Google Authenticator) or a hardware key.
3. Scan the QR code, enter two consecutive codes to confirm.
4. Immediately create an IAM admin user (below) and log out of root.

## Lab 1.2 — Create an IAM Admin User, Group, and Password Policy

```bash
# Create a group for administrators
aws iam create-group --group-name Administrators

# Attach the AWS-managed AdministratorAccess policy to the group
aws iam attach-group-policy \
  --group-name Administrators \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create yourself an IAM user
aws iam create-user --user-name jdoe-admin

# Add the user to the Administrators group
aws iam add-user-to-group --user-name jdoe-admin --group-name Administrators

# Give the user console access with a temporary password (forces reset on login)
aws iam create-login-profile \
  --user-name jdoe-admin \
  --password 'TempPassw0rd!2026' \
  --password-reset-required
```

Set an account-wide password policy so every future IAM user inherits sane defaults:

```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 5
```

Now enable MFA on this IAM user the same way you did for root (IAM → Users → Security credentials → Assign MFA device), and use *this* user for everything going forward.

## Lab 1.3 — Custom Least-Privilege Policy (JSON)

Say you want a user who can only manage objects in one S3 bucket — nothing else. Instead of `AdministratorAccess`, write a scoped policy.

Save as `s3-project-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListSpecificBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-project-bucket"
    },
    {
      "Sid": "ReadWriteObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::my-project-bucket/*"
    }
  ]
}
```

Create and attach it:

```bash
aws iam create-policy \
  --policy-name S3ProjectBucketAccess \
  --policy-document file://s3-project-policy.json

aws iam create-group --group-name S3ProjectUsers

aws iam attach-group-policy \
  --group-name S3ProjectUsers \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/S3ProjectBucketAccess
```

## Lab 1.4 — Explicit Deny vs. Default Deny

By default, IAM denies everything unless a policy explicitly allows it (**default deny**). But you can also write an **explicit deny**, which overrides *any* allow, from *any* policy, no matter how permissive.

Test this by attaching an explicit deny for `s3:DeleteObject` on top of the policy above.

Save as `deny-delete-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ExplicitlyDenyDelete",
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::my-project-bucket/*"
    }
  ]
}
```

```bash
aws iam create-policy \
  --policy-name DenyDeleteOnProjectBucket \
  --policy-document file://deny-delete-policy.json

aws iam attach-group-policy \
  --group-name S3ProjectUsers \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/DenyDeleteOnProjectBucket
```

Now try deleting an object as a user in this group — it fails, even though the first policy explicitly allowed `s3:DeleteObject`. This demonstrates AWS's evaluation order:

1. **Explicit Deny** → if any statement anywhere denies it, request fails. Full stop.
2. **Explicit Allow** → if no deny matched, and any statement allows it, request succeeds.
3. **Default Deny** → if nothing matched at all, request fails.

This ordering is why SCPs and permission boundaries (covered in [03](../03-organizations-scps-billing-guardrails/README.md)) are so powerful — a single deny at the org level can override every allow beneath it.

---

**Next:** [02 — IAM Roles, Federation & STS](../02-iam-roles-federation-sts/README.md)
