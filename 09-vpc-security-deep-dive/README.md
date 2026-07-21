# 09 — VPC Security Deep Dive

## Theory: Private Connectivity, Egress Control & Segmentation

By now you have a VPC with public/private subnets, layered SG/NACL filtering, keyless SSM access, and a load-balanced, auto-scaling app tier. This section closes the loop on two questions that haven't come up yet: **can you see what's actually happening on the network**, and **can you talk to AWS services without ever touching the public internet at all**.

- **VPC Flow Logs** capture metadata about the IP traffic going to and from network interfaces in your VPC — source/destination IP, port, protocol, byte counts, and crucially, whether the traffic was `ACCEPT`ed or `REJECT`ed by an SG or NACL. This is your evidence trail for "is something scanning my private subnet" or "why can't this instance reach that endpoint."
- A **VPC Endpoint** lets resources in your VPC reach an AWS service (like S3 or DynamoDB) using AWS's private network backbone instead of routing out through the IGW/NAT Gateway to the public internet. A **Gateway endpoint** (S3, DynamoDB only) works by adding a route table entry; an **Interface endpoint** (most other services) works by placing an ENI with a private IP directly in your subnet. Either way, traffic to that service never touches the internet, which is both a security win (no exposure) and often a cost win (no NAT Gateway data-processing charges for that traffic).
- **Transit Gateway** and **VPC Peering** are how you connect *multiple* VPCs together. Peering is a 1:1 mesh — fine for a handful of VPCs, unmanageable past a dozen (`n(n-1)/2` connections). Transit Gateway is a central hub: every VPC attaches once, and the Transit Gateway routes between them, which is what most real organizations use once they're past 3–4 VPCs. This is **network segmentation** at the org level — the same instinct as the SCP guardrails from Topic 1, applied to network reachability instead of IAM permissions.

## Lab 9.1 — Enable VPC Flow Logs to CloudWatch Logs, Query Rejected Traffic

```bash
# IAM role that lets Flow Logs write to CloudWatch Logs
cat > flow-logs-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "vpc-flow-logs.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name VPCFlowLogsRole \
  --assume-role-policy-document file://flow-logs-trust-policy.json

aws iam attach-role-policy \
  --role-name VPCFlowLogsRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/VPCFlowLogsDeliveryRolePolicy

# Create the CloudWatch Logs group
aws logs create-log-group --log-group-name /vpc/flow-logs/security-lab-vpc

# Enable Flow Logs on the whole VPC (ALL = both accepted and rejected traffic)
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids <VPC_ID> \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /vpc/flow-logs/security-lab-vpc \
  --deliver-logs-permission-arn arn:aws:iam::<ACCOUNT_ID>:role/VPCFlowLogsRole
```

Query for rejected traffic using CloudWatch Logs Insights:

```bash
aws logs start-query \
  --log-group-name /vpc/flow-logs/security-lab-vpc \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, srcAddr, dstAddr, dstPort, action
                   | filter action = "REJECT"
                   | sort @timestamp desc
                   | limit 50'

# Fetch results once the query finishes running
aws logs get-query-results --query-id <QUERY_ID_FROM_ABOVE>
```

A pattern of `REJECT` entries hitting the same destination port from many different source IPs is a classic port-scan signature — this is exactly the kind of thing the NACL deny rule from Section 6 would be generating log entries for.

## Lab 9.2 — Gateway VPC Endpoint for S3

```bash
# Create the S3 Gateway endpoint, associated with the private route table from Section 5
aws ec2 create-vpc-endpoint \
  --vpc-id <VPC_ID> \
  --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids <PRIVATE_RT_ID> \
  --vpc-endpoint-type Gateway
```

AWS silently adds a route in `<PRIVATE_RT_ID>` for S3's IP prefix list, pointed at the endpoint instead of the NAT Gateway. Confirm it:

```bash
aws ec2 describe-route-tables --route-table-ids <PRIVATE_RT_ID>
```

Test from an SSM session on a private-subnet instance (Section 7's connection method):

```bash
aws s3 ls s3://my-project-bucket/
```

This now succeeds without the traffic ever going through the NAT Gateway or IGW — you can confirm by watching NAT Gateway `BytesOutToDestination` in CloudWatch metrics stay flat during the request. For tighter control, attach an endpoint policy restricting which buckets the endpoint can reach, the same way you'd scope an IAM policy:

```bash
cat > s3-endpoint-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::my-project-bucket",
        "arn:aws:s3:::my-project-bucket/*"
      ]
    }
  ]
}
EOF

aws ec2 modify-vpc-endpoint \
  --vpc-endpoint-id <ENDPOINT_ID> \
  --policy-document file://s3-endpoint-policy.json
```

## Lab 9.3 (Stretch) — Transit Gateway vs. VPC Peering, Conceptually

No build required here — just reason through the diagram below and the tradeoffs.

```
VPC Peering (mesh — gets unmanageable fast):

   VPC-A ─────── VPC-B
     │  ╲        ╱  │
     │    ╲    ╱    │
     │      ╲╱      │
     │      ╱╲      │
     │    ╱    ╲    │
     │  ╱        ╲  │
   VPC-C ─────── VPC-D

   4 VPCs = 6 peering connections (n(n-1)/2)
   Each connection needs its own route table entries on both sides
   No transitive routing: A-B and B-C peered does NOT let A reach C


Transit Gateway (hub — scales cleanly):

           VPC-A
             │
   VPC-D ── [ TGW ] ── VPC-B
             │
           VPC-C

   4 VPCs = 4 attachments, one per VPC
   TGW route tables control what can reach what (segmentation)
   Adding a 5th VPC = 1 new attachment, not 4 new peering connections
```

Peering is fine for a couple of VPCs that need full-mesh reachability (e.g., a shared-services VPC talking to one app VPC). The moment you're planning for prod/dev/sandbox/security-tooling accounts each with their own VPC — the exact multi-account layout from Topic 1's Organizations section — Transit Gateway is what lets you centrally control which of those VPCs can reach which others, without an ever-growing web of point-to-point connections and without giving every VPC blanket access to every other one.

---

**Previous:** [08 — Load Balancing & Auto Scaling](../08-load-balancing-and-auto-scaling/README.md)

