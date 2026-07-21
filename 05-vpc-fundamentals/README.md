# 05 — VPC Fundamentals

## Theory: CIDR, Subnetting & the Public/Private Split

A **VPC** (Virtual Private Cloud) is your own isolated network inside AWS, defined by a **CIDR block** — a range of IP addresses expressed as `10.0.0.0/16`, meaning the first 16 bits are fixed (the network) and the remaining 16 bits are available for hosts (65,536 addresses). You then carve that block into smaller **subnets**, each pinned to a single **Availability Zone (AZ)**.

The public/private distinction isn't a property of the subnet itself — it's determined entirely by the subnet's **route table**:

- A **public subnet** has a route to an **Internet Gateway (IGW)** — a horizontally scaled, redundant gateway that lets resources with a public IP reach and be reached from the internet.
- A **private subnet** has no route to an IGW. Resources inside it can't be reached directly from the internet, and can't reach out either — unless you give them a path via a **NAT Gateway**.

A **NAT Gateway** sits in a public subnet, has its own Elastic IP, and lets private-subnet resources initiate *outbound* connections (e.g., pulling OS updates) while remaining unreachable from the internet *inbound*. This asymmetry — outbound yes, inbound no — is the core of why private subnets are safer for databases and internal app servers.

Spreading subnets across two AZs is what gives you **fault tolerance**: if one AZ has an outage, the other keeps serving traffic. This groundwork is what Sections 6–9 build security on top of, and what Section 8 uses for high availability.

## Lab 5.1 — Build a Custom VPC: CIDR Block, 2 Public + 2 Private Subnets Across 2 AZs

```bash
# Create the VPC
aws ec2 create-vpc \
  --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=security-lab-vpc}]'

# Note the VpcId from the output, then enable DNS support/hostnames
aws ec2 modify-vpc-attribute --vpc-id <VPC_ID> --enable-dns-support
aws ec2 modify-vpc-attribute --vpc-id <VPC_ID> --enable-dns-hostnames

# Public subnet A (AZ 1)
aws ec2 create-subnet \
  --vpc-id <VPC_ID> \
  --cidr-block 10.0.0.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=public-subnet-a}]'

# Public subnet B (AZ 2)
aws ec2 create-subnet \
  --vpc-id <VPC_ID> \
  --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1b \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=public-subnet-b}]'

# Private subnet A (AZ 1)
aws ec2 create-subnet \
  --vpc-id <VPC_ID> \
  --cidr-block 10.0.10.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=private-subnet-a}]'

# Private subnet B (AZ 2)
aws ec2 create-subnet \
  --vpc-id <VPC_ID> \
  --cidr-block 10.0.11.0/24 \
  --availability-zone us-east-1b \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=private-subnet-b}]'
```

`/24` gives each subnet 256 addresses (251 usable — AWS reserves 5 per subnet). Splitting `10.0.0.0/16` this way leaves plenty of room to add more subnets later without re-architecting.

## Lab 5.2 — Attach an Internet Gateway, Configure Route Tables for Public Subnets

```bash
# Create and attach the IGW
aws ec2 create-internet-gateway \
  --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=security-lab-igw}]'

aws ec2 attach-internet-gateway \
  --vpc-id <VPC_ID> \
  --internet-gateway-id <IGW_ID>

# Create a route table for public subnets
aws ec2 create-route-table \
  --vpc-id <VPC_ID> \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=public-rt}]'

# Add a default route (0.0.0.0/0) pointing at the IGW
aws ec2 create-route \
  --route-table-id <PUBLIC_RT_ID> \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id <IGW_ID>

# Associate both public subnets with this route table
aws ec2 associate-route-table --route-table-id <PUBLIC_RT_ID> --subnet-id <PUBLIC_SUBNET_A_ID>
aws ec2 associate-route-table --route-table-id <PUBLIC_RT_ID> --subnet-id <PUBLIC_SUBNET_B_ID>

# Make sure instances in public subnets actually get a public IP on launch
aws ec2 modify-subnet-attribute --subnet-id <PUBLIC_SUBNET_A_ID> --map-public-ip-on-launch
aws ec2 modify-subnet-attribute --subnet-id <PUBLIC_SUBNET_B_ID> --map-public-ip-on-launch
```

A subnet is "public" purely because its route table sends `0.0.0.0/0` to an IGW — nothing else about it is special. This is worth internalizing: security posture here is a routing decision, not a subnet property.

## Lab 5.3 — Launch a NAT Gateway for Private Subnet Outbound Access

```bash
# Allocate an Elastic IP for the NAT Gateway
aws ec2 allocate-address --domain vpc

# Create the NAT Gateway in a PUBLIC subnet (it needs internet reachability itself)
aws ec2 create-nat-gateway \
  --subnet-id <PUBLIC_SUBNET_A_ID> \
  --allocation-id <EIP_ALLOCATION_ID> \
  --tag-specifications 'ResourceType=natgateway,Tags=[{Key=Name,Value=security-lab-nat}]'

# Wait for it to become available (can take a few minutes)
aws ec2 describe-nat-gateways --nat-gateway-ids <NAT_GW_ID>

# Create a route table for private subnets
aws ec2 create-route-table \
  --vpc-id <VPC_ID> \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=private-rt}]'

# Route outbound traffic through the NAT Gateway
aws ec2 create-route \
  --route-table-id <PRIVATE_RT_ID> \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id <NAT_GW_ID>

# Associate both private subnets
aws ec2 associate-route-table --route-table-id <PRIVATE_RT_ID> --subnet-id <PRIVATE_SUBNET_A_ID>
aws ec2 associate-route-table --route-table-id <PRIVATE_RT_ID> --subnet-id <PRIVATE_SUBNET_B_ID>
```

**Cost note:** a NAT Gateway bills hourly plus per-GB processed, and is *not* Free Tier eligible. If you're optimizing for cost over realism, you can substitute a **NAT instance** — a small EC2 instance running NAT software with `Source/Dest Check` disabled — but NAT Gateway is what you'll see in real production environments and is worth the few dollars for the lab.

```bash
# Only if using a NAT instance instead: disable the source/dest check
aws ec2 modify-instance-attribute \
  --instance-id <NAT_INSTANCE_ID> \
  --no-source-dest-check
```

By the end of this lab you have a VPC where public subnets can reach (and be reached by) the internet directly, and private subnets can reach *out* through the NAT Gateway but can't be reached *in* — the foundation the rest of Topic 2 builds on.

---

**Next:** [06 — Security Groups & NACLs](../06-security-groups-and-nacls/README.md)
