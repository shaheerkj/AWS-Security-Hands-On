# 10 — S3 Fundamentals & Public Access

## Theory: Bucket Policies vs. IAM Policies vs. ACLs, and the "Open S3 Bucket" Pattern

S3 access can be controlled by three overlapping mechanisms, and confusing them is exactly how buckets end up exposed:

- **IAM policies** — attached to a user/role/group (identity-based, from [01](../01-account-hardening-iam-basics/README.md)). Answers "what can this identity do, across any bucket it touches?"
- **Bucket policies** — a resource-based policy attached directly to the bucket. Answers "who can act on this specific bucket?" Critically, a bucket policy can grant access to `Principal: "*"` — literally anyone on the internet — with no IAM policy involved at all.
- **ACLs (Access Control Lists)** — the oldest, coarsest mechanism, largely legacy now. AWS disables ACLs by default on new buckets (Bucket Owner Enforced), and you should generally leave them off in favor of policies.

The classic breach pattern — the one behind a huge fraction of real-world "S3 data leak" headlines — is a bucket policy (or ACL) that grants public read access, usually added for a legitimate-seeming reason ("I just need this one file reachable from a script") and then never revisited. **Block Public Access** exists specifically to make that mistake structurally harder: it's a setting that can override permissive bucket policies/ACLs at both the account and bucket level, so even if someone writes a public-granting policy later, it doesn't take effect unless Block Public Access is explicitly turned off first.

## Lab 10.1 — Private Bucket, Block Public Access at Account and Bucket Level

```bash
# Create a private bucket (private is the default — no extra flag needed)
aws s3api create-bucket \
  --bucket my-data-lab-2026 \
  --region us-east-1

# Enable Block Public Access at the ACCOUNT level — applies to every bucket, present and future
aws s3control put-public-access-block \
  --account-id <ACCOUNT_ID> \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Also set it explicitly at the BUCKET level (belt and suspenders — some orgs manage these independently)
aws s3api put-public-access-block \
  --bucket my-data-lab-2026 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

The four settings do different jobs: `BlockPublicAcls`/`IgnorePublicAcls` stop new/existing ACLs from granting public access, and `BlockPublicPolicy`/`RestrictPublicBuckets` do the same for bucket policies. Turning on all four is the right default for the overwhelming majority of buckets — you opt out per-bucket only when you have a deliberate, reviewed reason to host public content (e.g., static website assets).

## Lab 10.2 — Deliberately Expose an Object, Then Find and Fix It

First, temporarily disable Block Public Access on this one bucket so the demo policy can actually take effect:

```bash
aws s3api put-public-access-block \
  --bucket my-data-lab-2026 \
  --public-access-block-configuration \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
```

Upload a test object, then attach a bucket policy that makes it public. Save as `public-object-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadOneObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-data-lab-2026/test-object.txt"
    }
  ]
}
```

```bash
echo "sensitive-looking content" > test-object.txt
aws s3 cp test-object.txt s3://my-data-lab-2026/test-object.txt

aws s3api put-bucket-policy \
  --bucket my-data-lab-2026 \
  --policy file://public-object-policy.json

# Confirm it's actually public (should succeed with no credentials)
curl -s https://my-data-lab-2026.s3.amazonaws.com/test-object.txt
```

Now **find** it the way you'd actually discover this in a real account — with **IAM Access Analyzer**, which specifically hunts for resources shared outside your account/org:

```bash
# Create an analyzer scoped to your account (or "ORGANIZATION" if run from the management account)
aws accessanalyzer create-analyzer \
  --analyzer-name s3-public-check \
  --type ACCOUNT

# List findings — this will surface the public bucket policy you just created
aws accessanalyzer list-findings \
  --analyzer-arn <ANALYZER_ARN>
```

**Fix** it two ways — remove the offending policy, and re-enable Block Public Access so this class of mistake can't recur:

```bash
aws s3api delete-bucket-policy --bucket my-data-lab-2026

aws s3api put-public-access-block \
  --bucket my-data-lab-2026 \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Confirm it's gone
curl -s -o /dev/null -w "%{http_code}\n" https://my-data-lab-2026.s3.amazonaws.com/test-object.txt
# should now return 403
```

This find-then-fix loop — Access Analyzer flags it, you remove the policy, you re-enable the account-level guardrail — is the real-world incident response pattern for exactly this class of finding.

## Lab 10.3 — Enable Versioning and a Lifecycle Policy

```bash
# Enable versioning — protects against accidental overwrite/delete, and is a prerequisite for some backup/DR patterns
aws s3api put-bucket-versioning \
  --bucket my-data-lab-2026 \
  --versioning-configuration Status=Enabled
```

Save as `lifecycle-policy.json` — transition older versions to cheaper storage, then expire them:

```json
{
  "Rules": [
    {
      "ID": "TransitionAndExpireOldVersions",
      "Status": "Enabled",
      "Filter": {},
      "NoncurrentVersionTransitions": [
        {
          "NoncurrentDays": 30,
          "StorageClass": "STANDARD_IA"
        }
      ],
      "NoncurrentVersionExpiration": {
        "NoncurrentDays": 90
      },
      "AbortIncompleteMultipartUpload": {
        "DaysAfterInitiation": 7
      }
    }
  ]
}
```

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket my-data-lab-2026 \
  --lifecycle-configuration file://lifecycle-policy.json
```

With versioning on, a `DeleteObject` doesn't actually erase data — it just adds a delete marker, and the previous version is still recoverable. The lifecycle rule above keeps that safety net from becoming an unbounded storage bill: old versions move to cheaper storage after 30 days and are permanently expired after 90.

---

**Previous:** [09 — VPC Security Deep Dive](../09-vpc-security-deep-dive/README.md)
**Next:** [11 — Encryption & KMS](../11-encryption-and-kms/README.md)
