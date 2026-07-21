# 12 — Secrets & Credential Management

## Theory: Why Hardcoded Credentials Are a Top Breach Cause

A hardcoded database password, API key, or access key in application code has three properties that make it a recurring cause of real breaches: it's **static** (never rotates unless someone remembers to), it's **wherever the code goes** (dev laptops, CI logs, container images, and — very often — accidentally committed to a public git repo), and it's **invisible to network-layer controls** — an SG or NACL can't stop someone who already has the credential itself. Sections [01](../01-account-hardening-iam-basics/README.md) and [02](../02-iam-roles-federation-sts/README.md) covered this same problem for AWS API credentials specifically (solved with IAM roles + STS temporary credentials); this section covers the parallel problem for *application-level* secrets like database passwords, third-party API keys, and TLS private keys, which IAM roles alone don't solve.

**AWS Secrets Manager** stores secrets centrally, encrypted with KMS, and lets your application fetch them at runtime via an API call authorized by IAM — the secret itself never lives in code, config files, or environment variables baked into an image. It also supports **automatic rotation**: for supported databases (RDS included), Secrets Manager can rotate the credential on a schedule using a Lambda function it manages, updating both the secret's value and the database's actual password in the same operation, with zero manual intervention.

**SSM Parameter Store** (specifically its `SecureString` type) does something similar — KMS-encrypted values fetched at runtime via IAM-authorized API calls — but with a narrower feature set and (at standard tier) no cost, versus Secrets Manager's per-secret monthly charge plus built-in rotation tooling.

## Lab 12.1 — Store a DB Credential in Secrets Manager, Retrieve via IAM Role

```bash
# Store the secret as a JSON blob (Secrets Manager understands key/value structure natively)
aws secretsmanager create-secret \
  --name prod/app-db-credentials \
  --description "App database credentials for the data lab" \
  --secret-string '{"username":"appuser","password":"Tr0ub4dor&3Init!"}'
```

Create an IAM policy that allows reading *only this specific secret*, save as `secrets-read-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:<ACCOUNT_ID>:secret:prod/app-db-credentials-*"
    }
  ]
}
```

```bash
aws iam create-policy \
  --policy-name AppDBSecretRead \
  --policy-document file://secrets-read-policy.json

# Attach it to the app instance's role from Section 7 (EC2-SSM-Role), or a Lambda execution role
aws iam attach-role-policy \
  --role-name EC2-SSM-Role \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/AppDBSecretRead
```

The trailing `-*` on the resource ARN matters: Secrets Manager appends a random 6-character suffix to every secret's full ARN, so an exact-match ARN would never actually match at runtime.

From inside the instance (via the SSM session from [07](../07-ec2-bastion-ssm-patch-hygiene/README.md) — no SSH needed):

```bash
aws secretsmanager get-secret-value \
  --secret-id prod/app-db-credentials \
  --query SecretString \
  --output text
```

In application code, this is typically one SDK call at startup, cached in memory — never written to disk, never logged, never in an environment variable that might get dumped in a crash report:

```python
import boto3, json

client = boto3.client("secretsmanager", region_name="us-east-1")
response = client.get_secret_value(SecretId="prod/app-db-credentials")
creds = json.loads(response["SecretString"])
# creds["username"], creds["password"] — used to connect, never persisted
```

## Lab 12.2 — Secrets Manager vs. SSM Parameter Store (SecureString)

```bash
# Store the same kind of value in Parameter Store instead, encrypted with the CMK from Section 11
aws ssm put-parameter \
  --name /app/db/password \
  --value "Tr0ub4dor&3Init!" \
  --type SecureString \
  --key-id alias/data-lab-cmk

# Retrieve it (--with-decryption is required, or you get the ciphertext back)
aws ssm get-parameter \
  --name /app/db/password \
  --with-decryption \
  --query Parameter.Value \
  --output text
```

| | Secrets Manager | SSM Parameter Store (SecureString) |
|---|---|---|
| Cost | ~$0.40/secret/month + API calls | Standard tier: free; Advanced tier: small monthly fee |
| Native rotation | Built-in, scheduled, Lambda-managed, RDS/Redshift/DocumentDB integration | None built-in — you'd write and schedule your own rotation logic |
| Structured values | Native JSON key/value support | Plain string only (you can store JSON as text, but no native parsing) |
| Cross-account sharing | Native resource policies for cross-account access | More manual |
| Best fit | Database credentials, API keys needing rotation, anything compliance-sensitive | App config, feature flags, simple secrets where rotation isn't required |

The practical guidance: use **Secrets Manager** for anything that should rotate (database credentials especially) or that benefits from structured JSON storage; use **Parameter Store SecureString** for simpler, lower-churn secrets and general app configuration where the cost of Secrets Manager isn't justified. Both are strictly better than the alternative this section opened with — nothing goes in code or a config file checked into git, ever.

---

**Previous:** [11 — Encryption & KMS](../11-encryption-and-kms/README.md)
**Next:** [13 — Databases & RDS Security](../13-databases-and-rds-security/README.md)
