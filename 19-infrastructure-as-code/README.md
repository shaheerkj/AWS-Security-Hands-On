# 19 — Infrastructure as Code

## Theory: Reproducibility, "Shift-Left" Security, and Drift Detection

Every lab up to this point has been a manual CLI walkthrough — reproducible if you follow the steps again, but not actually **codified**. **Infrastructure as Code (IaC)** — CloudFormation or Terraform being the two most common on AWS — means the *desired state* of your infrastructure lives in version-controlled text files, and a tool reconciles reality to match that text, rather than a human running commands from memory (or from a runbook like this repo).

**Reproducibility** is the most obvious win: the VPC/SG/EC2 setup from [05](../05-vpc-fundamentals/README.md)–[06](../06-security-groups-and-nacls/README.md) becomes a template you can deploy identically into a fresh account in minutes, rather than re-typing dozens of `aws` commands and hoping you didn't miss a flag.

**"Shift-left" security** means catching misconfigurations *before* they're ever deployed, by scanning the template itself — as opposed to Section 4/16's Config/Security Hub, which catch misconfigurations *after* deployment, once a resource already exists and is potentially already exposed. Tools like `cfn-lint`, `checkov`, and `tfsec` read your template statically and flag the same categories of problem Config rules would flag at runtime (a security group open to `0.0.0.0/0` on port 22, an unencrypted S3 bucket, a public RDS instance) — but they do it in a CI pipeline, before `apply`/`deploy` ever runs, which is both cheaper (no cleanup of a real misconfigured resource) and faster (feedback in seconds, in a pull request, rather than discovered hours later by a Config evaluation).

**Drift detection** addresses a problem specific to IaC: once infrastructure is deployed from a template, someone can still go into the console and change something by hand (bump a security group rule, resize an instance) — now the template no longer accurately describes reality. Both CloudFormation and Terraform can detect this **drift**, comparing actual deployed state against what the template declares, which matters for security specifically because an out-of-band change is exactly how a "temporary" open SG rule from an incident investigation quietly becomes permanent.

## Lab 19.1 — Recreate a Piece of Days 5–8 as a CloudFormation Template

This template recreates a minimal slice: a VPC, one public subnet, an IGW, and one EC2 instance with a locked-down SG — the smallest reproducible piece of Sections 5–6. Save as `mini-network.yaml`:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: Minimal VPC + public subnet + EC2 + SG, mirroring Days 5-6

Parameters:
  AdminCidr:
    Type: String
    Description: Your IP in CIDR form, e.g. 203.0.113.10/32

Resources:
  LabVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.1.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: Name
          Value: iac-lab-vpc

  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref LabVPC
      CidrBlock: 10.1.0.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: iac-lab-public-subnet

  IGW:
    Type: AWS::EC2::InternetGateway

  IGWAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref LabVPC
      InternetGatewayId: !Ref IGW

  PublicRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref LabVPC

  PublicRoute:
    Type: AWS::EC2::Route
    DependsOn: IGWAttachment
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref IGW

  PublicRouteAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref PublicSubnet
      RouteTableId: !Ref PublicRouteTable

  InstanceSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: SSH from admin IP only - no 0.0.0.0/0
      VpcId: !Ref LabVPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: !Ref AdminCidr

  LabInstance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t2.micro
      ImageId: ami-0abcdef1234567890
      SubnetId: !Ref PublicSubnet
      SecurityGroupIds:
        - !Ref InstanceSG
      Tags:
        - Key: Name
          Value: iac-lab-instance

Outputs:
  VpcId:
    Value: !Ref LabVPC
  InstanceId:
    Value: !Ref LabInstance
```

Deploy it:

```bash
aws cloudformation deploy \
  --template-file mini-network.yaml \
  --stack-name iac-lab \
  --parameter-overrides AdminCidr=<YOUR_IP>/32
```

**Terraform equivalent**, for comparison — save as `mini-network.tf`:

```hcl
variable "admin_cidr" {
  type        = string
  description = "Your IP in CIDR form, e.g. 203.0.113.10/32"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "iac-lab-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.1.0.0/24"
  map_public_ip_on_launch = true
  tags = { Name = "iac-lab-public-subnet" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lab.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "instance" {
  description = "SSH from admin IP only - no 0.0.0.0/0"
  vpc_id      = aws_vpc.lab.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}

resource "aws_instance" "lab" {
  ami                    = "ami-0abcdef1234567890"
  instance_type           = "t2.micro"
  subnet_id               = aws_subnet.public.id
  vpc_security_group_ids  = [aws_security_group.instance.id]
  tags = { Name = "iac-lab-instance" }
}
```

```bash
terraform init
terraform plan -var="admin_cidr=<YOUR_IP>/32"
terraform apply -var="admin_cidr=<YOUR_IP>/32"
```

## Lab 19.2 — Scan the Template Before Deploy

```bash
# cfn-lint: catches CloudFormation syntax and best-practice issues
pip install cfn-lint --break-system-packages
cfn-lint mini-network.yaml

# checkov: broader policy-as-code scanner, works on both CloudFormation and Terraform
pip install checkov --break-system-packages
checkov -f mini-network.yaml
checkov -d . --framework terraform

# tfsec: Terraform-specific security scanner
tfsec .
```

Deliberately introduce a misconfiguration to see the scanners catch it — change `CidrIp: !Ref AdminCidr` to `CidrIp: 0.0.0.0/0` in the CloudFormation template (or the Terraform equivalent), then rerun:

```bash
checkov -f mini-network.yaml --check CKV_AWS_24
# flags: Security Group allows unrestricted ingress
```

This is the exact class of mistake Lab 6.1 walked through building correctly by hand — the difference now is that a CI pipeline running `checkov` on every pull request catches it automatically, before anyone approves the change, rather than relying on a human reviewer noticing a `0.0.0.0/0` buried in a diff. Revert the change once you've confirmed the scanner catches it.

## Lab 19.3 — Drift Detection

Make an out-of-band change via the console or CLI — something a well-meaning teammate might do without going back to update the template:

```bash
# Manually widen the SG rule outside of CloudFormation/Terraform
aws ec2 authorize-security-group-ingress \
  --group-id <INSTANCE_SG_ID> \
  --protocol tcp --port 443 \
  --cidr 0.0.0.0/0
```

**CloudFormation** drift detection:

```bash
aws cloudformation detect-stack-drift --stack-name iac-lab

# Note the StackDriftDetectionId from the output, then poll for results
aws cloudformation describe-stack-drift-detection-status \
  --stack-drift-detection-id <DETECTION_ID>

aws cloudformation describe-stack-resource-drifts \
  --stack-name iac-lab
```

**Terraform** achieves the same thing simply by re-running `plan` — it always compares live state against the template:

```bash
terraform plan -var="admin_cidr=<YOUR_IP>/32"
# shows the unexpected 443 rule as something Terraform wants to remove,
# since it's not declared in the .tf file
```

Both tools will flag the manually-added rule as drift. Reconcile it by either updating the template to declare the change deliberately (if it was actually intended) or running `terraform apply`/a CloudFormation update to snap the resource back to the declared state (if it wasn't) — the point of drift detection is forcing that decision to be explicit rather than letting undeclared changes accumulate silently.

Clean up before moving to the capstone:

```bash
aws cloudformation delete-stack --stack-name iac-lab
# or
terraform destroy -var="admin_cidr=<YOUR_IP>/32"
```

---

**Previous:** [18 — Serverless & Least-Privilege Functions](../18-serverless-and-least-privilege-functions/README.md)
**Next:** [20 — Capstone: Secure 3-Tier Architecture Review](../20-capstone-secure-3tier-architecture-review/README.md)
