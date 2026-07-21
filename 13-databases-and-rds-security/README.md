# 13 — Databases & RDS Security

## Theory: Data Tier Isolation, Least-Privilege DB Users, and Encrypted Backups

The database is usually the most sensitive tier in any architecture — it's where the actual data lives, as opposed to the app tier which just processes it in transit. Everything built in Topic 2 was actually building toward this: the private subnets from [05](../05-vpc-fundamentals/README.md), the SG chaining pattern from [06](../06-security-groups-and-nacls/README.md), and the app-tier isolation from [08](../08-load-balancing-and-auto-scaling/README.md) all exist so that the database can be placed somewhere with **no path to the public internet at all** — not even outbound, in most cases — and reachable only from the specific app-tier resources that legitimately need it.

This is **data tier isolation**: the database has its own subnets, its own SG, and — ideally — its own AWS account or at minimum a clear network boundary, so that a compromise of a public-facing web server doesn't automatically mean a compromise of the data behind it. The SG rule for the DB port should name a *source security group* (the app tier's SG), the same chaining pattern from Section 6, never a broad CIDR — "only things wearing the app-sg badge can reach port 3306/5432" is a much stronger guarantee than "only things in this /24 can."

**Least-privilege DB users** is the same least-privilege principle from [01](../01-account-hardening-iam-basics/README.md), applied inside the database engine itself rather than at the AWS API layer: the application's DB user should have exactly the grants it needs (e.g., `SELECT`/`INSERT`/`UPDATE` on specific tables) and nothing resembling admin rights, so that a SQL injection vulnerability in the app can't be leveraged into dropping tables or reading unrelated schemas.

**Encrypted backups/snapshots** matter because a database snapshot is a full copy of your data — encrypting the live database but leaving snapshots unencrypted (or worse, sharing an unencrypted snapshot for a "quick test copy" and forgetting to lock down its access) is a surprisingly common way sensitive data leaks despite the primary instance being well-secured.

## Lab 13.1 — RDS Instance in a Private Subnet Only, No Public Access

RDS needs a **DB subnet group** spanning at least two AZs — reusing the private subnets from Section 5:

```bash
aws rds create-db-subnet-group \
  --db-subnet-group-name private-db-subnet-group \
  --db-subnet-group-description "Private subnets for RDS - no internet route" \
  --subnet-ids <PRIVATE_SUBNET_A_ID> <PRIVATE_SUBNET_B_ID>
```

Launch the instance with `--no-publicly-accessible` — this is the setting that determines whether RDS even *attempts* to assign a publicly resolvable endpoint, independent of subnet routing or SGs:

```bash
aws rds create-db-instance \
  --db-instance-identifier app-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --engine-version 16.3 \
  --master-username dbadmin \
  --master-user-password 'TempAdminPassw0rd!2026' \
  --allocated-storage 20 \
  --db-subnet-group-name private-db-subnet-group \
  --vpc-security-group-ids <DB_SG_ID> \
  --no-publicly-accessible \
  --storage-encrypted \
  --kms-key-id alias/data-lab-cmk \
  --backup-retention-period 7
```

Even without any SG rules at all, `--no-publicly-accessible` alone means RDS never provisions a public IP or public DNS resolution path for this instance — it's reachable only from inside the VPC, which is the correct default for essentially every database that isn't itself a public-facing service.

## Lab 13.2 — SG Restricting DB Access to the App Tier Only

```bash
# Create the DB's SG
aws ec2 create-security-group \
  --group-name db-sg \
  --description "RDS - Postgres from app tier only" \
  --vpc-id <VPC_ID>

# Allow Postgres (5432) ONLY from the app-sg created in Section 6
aws ec2 authorize-security-group-ingress \
  --group-id <DB_SG_ID> \
  --protocol tcp --port 5432 \
  --source-group <APP_SG_ID>
```

No other ingress rule exists on this SG — not from the bastion, not from your laptop, not from `0.0.0.0/0`. If you need to run an ad hoc admin query, the correct pattern is to `ssm start-session` (Section 7) into an app-tier instance and connect to the DB from *there*, rather than opening a rule for your own IP — the moment you add a personal-IP exception "just for now," you've reintroduced the exact broad-access pattern this whole lab is designed to avoid.

## Lab 13.3 — Encryption at Rest and Automated Backups

Encryption at rest was already set with `--storage-encrypted` and `--kms-key-id` in Lab 13.1 — worth calling out that **this can only be set at creation time**; an unencrypted RDS instance cannot be converted in place. If you inherit an unencrypted instance, the fix is: snapshot it, copy the snapshot with encryption enabled, then restore a new instance from the encrypted copy.

```bash
# If you ever need to encrypt an existing unencrypted instance:
aws rds create-db-snapshot \
  --db-instance-identifier app-db \
  --db-snapshot-identifier app-db-snapshot-unencrypted

aws rds copy-db-snapshot \
  --source-db-snapshot-identifier app-db-snapshot-unencrypted \
  --target-db-snapshot-identifier app-db-snapshot-encrypted \
  --kms-key-id alias/data-lab-cmk

aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier app-db-encrypted \
  --db-snapshot-identifier app-db-snapshot-encrypted \
  --db-subnet-group-name private-db-subnet-group \
  --no-publicly-accessible
```

Confirm automated backups are active and check retention (already set to 7 days above):

```bash
aws rds describe-db-instances \
  --db-instance-identifier app-db \
  --query 'DBInstances[0].[BackupRetentionPeriod,PreferredBackupWindow,StorageEncrypted]'
```

Finally, create a least-privilege application DB user *inside* the database itself — connect via `psql` from an app-tier SSM session, not as the master admin user day-to-day:

```sql
-- Run inside psql, connected as the master user, one-time setup
CREATE USER app_user WITH PASSWORD 'AppUserOwnPassw0rd!2026';
GRANT CONNECT ON DATABASE appdb TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
-- Deliberately no CREATE, DROP, or role-management grants
```

Store `app_user`'s password in Secrets Manager (Section 12) rather than the master credential — the application should never authenticate as `dbadmin` day-to-day, only the one-time setup and future schema migrations should.

---

**Previous:** [12 — Secrets & Credential Management](../12-secrets-and-credential-management/README.md)

