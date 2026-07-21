# 11 — Encryption & KMS

## Theory: Envelope Encryption, Key Policies vs. IAM, and Rotation

**AWS KMS (Key Management Service)** lets you create and control cryptographic keys without ever handling raw key material yourself. The core mechanism it uses is **envelope encryption**: rather than encrypting your actual data directly with your KMS key (slow, and KMS keys never leave KMS anyway), KMS generates a random **data key**, encrypts your data with that data key locally, then encrypts *the data key itself* with your KMS key. The encrypted data key gets stored alongside the encrypted data. To decrypt later, KMS decrypts the small data key, and you use it to decrypt the actual data — this is why encrypting a multi-GB EBS volume or S3 object is fast: KMS is only ever doing crypto operations on tiny data keys, not your bulk data.

A **Customer Managed Key (CMK)** is a KMS key you create and control, as opposed to an AWS-managed key (created automatically the first time a service needs one, with AWS controlling rotation and policy). CMKs matter for security because you control the **key policy** — a resource-based policy, similar in spirit to an S3 bucket policy, attached directly to the key. This is a second layer of access control *specific to KMS*: even if an IAM policy grants a user `kms:Decrypt`, the key policy must **also** allow it, or the request is denied. Key policies are how you separate "who can administer this key" from "who can just use it to encrypt/decrypt" — a meaningful separation of duties in regulated environments.

**Encryption at rest** protects data sitting in storage (S3, EBS, RDS); **encryption in transit** protects data moving over the network (TLS, covered via the ALB certificate in [08](../08-load-balancing-and-auto-scaling/README.md)). They're independent controls — you need both, and one doesn't substitute for the other. **Key rotation** — KMS can automatically generate new backing key material yearly for a CMK while keeping the same key ID/ARN, so nothing referencing the key breaks — limits how much data is ever encrypted under a single set of key material, bounding the blast radius if that material were ever somehow compromised.

## Lab 11.1 — Create a CMK, Encrypt an S3 Bucket and an EBS Volume With It

```bash
# Create the CMK (symmetric, the default and right choice for almost everything)
aws kms create-key \
  --description "CMK for S3 and EBS encryption lab" \
  --tags TagKey=Name,TagValue=data-lab-cmk

# Note the KeyId from the output, then give it a friendly alias
aws kms create-alias \
  --alias-name alias/data-lab-cmk \
  --target-key-id <KEY_ID>
```

Encrypt the S3 bucket from Section 10 with it (default bucket encryption — applies automatically to every future object, no per-upload flag needed):

```bash
aws s3api put-bucket-encryption \
  --bucket my-data-lab-2026 \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "aws:kms",
          "KMSMasterKeyID": "alias/data-lab-cmk"
        },
        "BucketKeyEnabled": true
      }
    ]
  }'
```

`BucketKeyEnabled: true` reduces KMS API call volume (and cost) by caching a bucket-level key for a short time, rather than calling KMS on every single object operation — worth turning on for any bucket with meaningful traffic.

Encrypt an EBS volume with the same CMK:

```bash
aws ec2 create-volume \
  --availability-zone us-east-1a \
  --size 20 \
  --volume-type gp3 \
  --encrypted \
  --kms-key-id alias/data-lab-cmk \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=data-lab-volume}]'
```

You can also make encryption the **account-level default** for all new EBS volumes in a region, so nobody has to remember the `--encrypted` flag:

```bash
aws ec2 enable-ebs-encryption-by-default --region us-east-1
aws ec2 modify-ebs-default-kms-key-id --kms-key-id alias/data-lab-cmk
```

## Lab 11.2 — Key Policy Restricting Who Can Use/Administer the Key

Save as `cmk-key-policy.json` — this splits **administration** (managing the key itself: rotation, deletion, policy changes) from **usage** (just encrypting/decrypting data with it):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootAccountFullAccess",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "KeyAdministratorsOnly",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/KeyAdminRole" },
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
