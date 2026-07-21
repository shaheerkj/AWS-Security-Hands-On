# 08 — Load Balancing & Auto Scaling

## Theory: High Availability, Horizontal Scaling & TLS Termination

An **Application Load Balancer (ALB)** distributes incoming traffic across a group of targets — here, EC2 instances managed by an **Auto Scaling Group (ASG)**. Spreading those targets across multiple AZs (the whole reason Section 5 built two public and two private subnets) means the loss of a single AZ doesn't take your app down — this is **high availability**.

An ASG adds **horizontal scaling**: instead of making one instance bigger (vertical scaling) to handle more load, you run more identical instances and let the ALB spread traffic across them, growing and shrinking the fleet automatically based on demand or schedule.

**TLS termination** at the ALB means the ALB — not your app instances — holds the SSL/TLS certificate and decrypts incoming HTTPS traffic, typically forwarding it to instances as plain HTTP inside the (private, trusted) VPC. This centralizes certificate management (via **ACM**, which auto-renews) instead of installing and rotating certs on every instance individually, and is why the `alb-sg` you built in Section 6 opens 443 to the world while `app-sg` only ever needs to hear from the ALB.

**Health checks** are what make this self-healing: the ALB continuously polls each target on a defined path (e.g., `/health`), stops routing traffic to any target that fails, and the ASG can be configured to terminate and replace unhealthy instances automatically.

## Lab 8.1 — ALB in Front of an ASG Across AZs

First, a **launch template** describing what an app instance looks like (reusing the `app-sg` and `EC2-SSM-Profile` from Sections 6–7):

```bash
aws ec2 create-launch-template \
  --launch-template-name app-server-template \
  --launch-template-data '{
    "ImageId": "ami-0abcdef1234567890",
    "InstanceType": "t2.micro",
    "SecurityGroupIds": ["<APP_SG_ID>"],
    "IamInstanceProfile": { "Name": "EC2-SSM-Profile" },
    "UserData": "'"$(echo -e '#!/bin/bash\nyum install -y httpd\nsystemctl enable httpd\nsystemctl start httpd\necho healthy > /var/www/html/health' | base64 -w0)"'"
  }'
```

Create a **target group** and the **ASG**, spanning both private subnets:

```bash
aws elbv2 create-target-group \
  --name app-tg \
  --protocol HTTP \
  --port 80 \
  --vpc-id <VPC_ID> \
  --health-check-path /health \
  --health-check-interval-seconds 15 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3

aws autoscaling create-auto-scaling-group \
  --auto-scaling-group-name app-asg \
  --launch-template "LaunchTemplateName=app-server-template,Version='$Latest'" \
  --min-size 2 \
  --max-size 4 \
  --desired-capacity 2 \
  --vpc-zone-identifier "<PRIVATE_SUBNET_A_ID>,<PRIVATE_SUBNET_B_ID>" \
  --target-group-arns <APP_TG_ARN> \
  --health-check-type ELB \
  --health-check-grace-period 60
```

`--health-check-type ELB` is important: it tells the ASG to trust the *ALB's* health check (hitting `/health` over HTTP), not just whether the instance is running — an instance can be "running" while its app process has crashed, and this setting catches that.

Now the ALB itself, spanning the two **public** subnets, using the `alb-sg` from Section 6:

```bash
aws elbv2 create-load-balancer \
  --name app-alb \
  --subnets <PUBLIC_SUBNET_A_ID> <PUBLIC_SUBNET_B_ID> \
  --security-groups <ALB_SG_ID> \
  --scheme internet-facing \
  --type application

# Note the LoadBalancerArn and DNSName from the output
```

## Lab 8.2 — Attach an ACM Certificate and Enforce HTTPS Redirect

```bash
# Request a public certificate for your domain (requires DNS or email validation)
aws acm request-certificate \
  --domain-name app.example.com \
  --validation-method DNS

# Follow the CNAME validation instructions in the console/output, then confirm issuance:
aws acm describe-certificate --certificate-arn <CERT_ARN>
```

Create the HTTPS listener, forwarding to the target group:

```bash
aws elbv2 create-listener \
  --load-balancer-arn <ALB_ARN> \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=<CERT_ARN> \
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
  --default-actions Type=forward,TargetGroupArn=<APP_TG_ARN>
```

Replace the default HTTP listener's action with a redirect to HTTPS, instead of forwarding traffic in the clear:

```bash
aws elbv2 create-listener \
  --load-balancer-arn <ALB_ARN> \
  --protocol HTTP \
  --port 80 \
  --default-actions '[{
    "Type": "redirect",
    "RedirectConfig": {
      "Protocol": "HTTPS",
      "Port": "443",
      "StatusCode": "HTTP_301"
    }
  }]'
```

Every plain-HTTP request now gets a `301` straight to HTTPS, and the ALB is the only place in your whole architecture holding a TLS certificate — the app instances never see the private key at all.

Hit the ALB's `DNSName` in a browser: you should get redirected to HTTPS automatically, and if you terminate one instance manually, the ASG replaces it and the ALB keeps serving traffic from the survivor in the meantime — that's high availability and self-healing working together.

---

**Previous:** [07 — EC2, Bastion/SSM & Patch Hygiene](../07-ec2-bastion-ssm-patch-hygiene/README.md)
**Next:** [09 — VPC Security Deep Dive](../09-vpc-security-deep-dive/README.md)
