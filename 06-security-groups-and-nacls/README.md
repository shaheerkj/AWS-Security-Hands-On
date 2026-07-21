# 06 — Security Groups & NACLs

## Theory: Stateful vs. Stateless, and Defense in Depth

AWS gives you two layers of network filtering, and understanding the difference between them is one of the most commonly-tested concepts in networking security:

- **Security Groups (SGs)** operate at the instance/ENI level and are **stateful**: if you allow inbound traffic on a port, the *response* traffic is automatically allowed out, regardless of outbound rules. SGs only support **allow** rules — there's no explicit deny.
- **Network ACLs (NACLs)** operate at the subnet level and are **stateless**: inbound and outbound rules are evaluated completely independently. If you allow inbound traffic, you must *also* explicitly allow the outbound response, or it gets dropped. NACLs support both **allow** and **deny** rules, evaluated in numbered order (lowest number wins).

This gives you **defense in depth**: even if an SG is misconfigured to be too permissive, a NACL can still block traffic at the subnet boundary before it ever reaches the instance. **SG chaining** — referencing one SG as the *source* of another SG's rule, rather than a raw CIDR — is how you express "only my ALB can talk to my app servers" without hardcoding IPs that might change.

## Lab 6.1 — Two EC2 Instances, SGs Restricted to Only Necessary Traffic

The scenario: a bastion host in the public subnet, an app instance in the private subnet, and (conceptually) an ALB that will front the app instance in Section 8. We want SSH to reach the app instance *only* via the bastion, and HTTP to reach it *only* via the ALB.

```bash
# SG for the bastion host — allow SSH only from your IP
aws ec2 create-security-group \
  --group-name bastion-sg \
  --description "Bastion host - SSH from admin IP only" \
  --vpc-id <VPC_ID>

aws ec2 authorize-security-group-ingress \
  --group-id <BASTION_SG_ID> \
  --protocol tcp --port 22 \
  --cidr <YOUR_IP>/32

# SG for the ALB (used again in Section 8) — allow HTTP/HTTPS from the internet
aws ec2 create-security-group \
  --group-name alb-sg \
  --description "ALB - public HTTP/HTTPS" \
  --vpc-id <VPC_ID>

aws ec2 authorize-security-group-ingress \
  --group-id <ALB_SG_ID> \
  --protocol tcp --port 80 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id <ALB_SG_ID> \
  --protocol tcp --port 443 \
  --cidr 0.0.0.0/0

# SG for the app instance — SSH ONLY from the bastion SG, HTTP ONLY from the ALB SG
aws ec2 create-security-group \
  --group-name app-sg \
  --description "App instance - SSH from bastion, HTTP from ALB only" \
  --vpc-id <VPC_ID>

aws ec2 authorize-security-group-ingress \
  --group-id <APP_SG_ID> \
  --protocol tcp --port 22 \
  --source-group <BASTION_SG_ID>

aws ec2 authorize-security-group-ingress \
  --group-id <APP_SG_ID> \
  --protocol tcp --port 80 \
  --source-group <ALB_SG_ID>
```

Notice `--source-group` instead of `--cidr` on the app SG rules — this is **SG chaining**. The rule says "traffic from anything wearing the bastion-sg or alb-sg badge," not "traffic from a specific IP range." If the ALB scales and adds new nodes with new IPs, the rule still works with zero changes.

```bash
# Launch the bastion in the public subnet
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --subnet-id <PUBLIC_SUBNET_A_ID> \
  --security-group-ids <BASTION_SG_ID> \
  --associate-public-ip-address \
  --key-name my-keypair \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=bastion}]'

# Launch the app instance in the private subnet — no public IP
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --subnet-id <PRIVATE_SUBNET_A_ID> \
  --security-group-ids <APP_SG_ID> \
  --key-name my-keypair \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=app-server}]'
```

Test it: SSH to the bastion's public IP, then from *inside* the bastion, SSH to the app instance's private IP using agent forwarding (`ssh -A`) or a copied key. Direct SSH from your laptop to the app instance's private IP should simply time out — there's no route to it at all, let alone an open port.

## Lab 6.2 — NACL Explicit Deny + Stateless vs. Stateful Behavior

```bash
# Create a NACL for the private subnets
aws ec2 create-network-acl \
  --vpc-id <VPC_ID> \
  --tag-specifications 'ResourceType=network-acl,Tags=[{Key=Name,Value=private-nacl}]'

# Rule 100: DENY inbound from a specific (hypothetical malicious) IP range
aws ec2 create-network-acl-entry \
  --network-acl-id <NACL_ID> \
  --rule-number 100 \
  --protocol -1 \
  --rule-action deny \
  --egress false \
  --cidr-block 203.0.113.0/24

# Rule 200: ALLOW all other inbound traffic (from within the VPC)
aws ec2 create-network-acl-entry \
  --network-acl-id <NACL_ID> \
  --rule-number 200 \
  --protocol -1 \
  --rule-action allow \
  --egress false \
  --cidr-block 10.0.0.0/16

# Outbound: explicitly allow, because NACLs are stateless
aws ec2 create-network-acl-entry \
  --network-acl-id <NACL_ID> \
  --rule-number 100 \
  --protocol -1 \
  --rule-action allow \
  --egress true \
  --cidr-block 0.0.0.0/0

# Associate with the private subnets
aws ec2 replace-network-acl-association \
  --association-id <CURRENT_ASSOC_ID_FOR_PRIVATE_SUBNET_A> \
  --network-acl-id <NACL_ID>
```

Rule numbers matter: AWS evaluates NACL rules **in ascending order** and stops at the first match. Deny-203.0.113.0/24 at rule 100 will always be checked *before* the broader allow at rule 200, so it takes precedence — this is different from SGs, which have no ordering because they only ever allow.

To feel the stateless vs. stateful difference directly: temporarily remove the outbound allow rule (rule 100 egress) on the NACL, then try to `curl` something from an instance in that subnet. The SG on the instance will happily allow the outbound request and the inbound response — but the NACL, having no memory of the outbound connection, will block the *return* traffic on the way back in unless you've explicitly allowed the corresponding inbound response too (typically on ephemeral ports 1024–65535). Re-add the outbound allow rule when you're done testing.

---

**Previous:** [05 — VPC Fundamentals](../05-vpc-fundamentals/README.md)
**Next:** [07 — EC2, Bastion/SSM & Patch Hygiene](../07-ec2-bastion-ssm-patch-hygiene/README.md)
