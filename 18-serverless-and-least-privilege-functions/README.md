# 18 — Serverless & Least-Privilege Functions

## Theory: Function-Level Least Privilege, Event-Driven Architecture, and Shared Responsibility for Serverless

Everything in Topics 1–4 assumed a long-running server — an EC2 instance with an IAM role attached ([02](../02-iam-roles-federation-sts/README.md)), sitting behind an ALB ([08](../08-load-balancing-and-auto-scaling/README.md)), patched and monitored continuously ([07](../07-ec2-bastion-ssm-patch-hygiene/README.md), [15](../15-guardduty-and-inspector/README.md)). **Lambda** removes the server entirely: your code runs only in response to an event, for the duration of that invocation, and AWS manages the underlying compute, OS, and patching.

This shifts — but doesn't eliminate — the security model. Under AWS's **shared responsibility model**, moving to serverless moves the line: AWS now owns patching the OS and runtime (things Section 7's Patch Manager labs handled for EC2), but you still own **function-level least privilege** (the IAM execution role), **your own code's vulnerabilities** (a SQL injection bug in your Lambda code is still your bug), **event source configuration** (who/what can trigger this function), and **secrets handling** (Section 12's guidance applies exactly the same to Lambda as to EC2 — no hardcoded credentials in function code).

**Function-level least privilege** is the same principle from [01](../01-account-hardening-iam-basics/README.md), applied at a much finer grain: an EC2 instance's role might reasonably need broad access because it runs many kinds of workloads over its lifetime, but a single Lambda function usually does *one thing* — this function only ever needs to read from one S3 bucket and write to one log group, so its execution role should say exactly that, nothing broader. This is easier to get right in serverless than on EC2 precisely because the function's job is so narrow — there's no excuse for a Lambda execution role carrying `s3:*` on `Resource: "*"`.

**Event-driven architecture** means the function has no listening port, no always-on network presence, and no SSH/SSM access surface at all — it simply wakes up when S3 (or API Gateway, EventBridge, SQS, etc.) invokes it. This collapses a huge portion of the attack surface this repo has spent 17 sections hardening (open ports, patch cadence, bastion access) — but only if the IAM side is done correctly, since the execution role becomes the *primary* thing standing between "event happened" and "arbitrary AWS access."

## Lab 18.1 — Lambda Triggered by S3 Upload, With a Scoped Execution Role

Write the function first. Save as `handler.py`:

```python
import boto3
import json

s3 = boto3.client("s3")

def lambda_handler(event, context):
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]
        response = s3.get_object(Bucket=bucket, Key=key)
        size = response["ContentLength"]
        print(f"Processed {key} from {bucket}: {size} bytes")
    return {"statusCode": 200, "body": json.dumps({"processed": len(event["Records"])})}
```

```bash
zip function.zip handler.py
```

Create the **scoped** execution role — `s3:GetObject` on this one bucket only, `logs:*` on this function's own log group only. Save the trust policy as `lambda-trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Save the permissions policy as `lambda-scoped-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyThisBucketOnly",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-data-lab-2026/*"
    },
    {
      "Sid": "LogsForThisFunctionOnly",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:<ACCOUNT_ID>:log-group:/aws/lambda/process-upload:*"
    }
  ]
}
```

```bash
aws iam create-role \
  --role-name process-upload-role \
  --assume-role-policy-document file://lambda-trust-policy.json

aws iam create-policy \
  --policy-name process-upload-scoped-policy \
  --policy-document file://lambda-scoped-policy.json

aws iam attach-role-policy \
  --role-name process-upload-role \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/process-upload-scoped-policy
```

Note what's *not* here: no `AWSLambdaBasicExecutionRole` managed policy attached wholesale (it grants `logs:*` on `Resource: "*"`, broader than needed), and no `s3:PutObject`/`s3:DeleteObject` (the function only ever reads). Create the function:

```bash
aws lambda create-function \
  --function-name process-upload \
  --runtime python3.12 \
  --role arn:aws:iam::<ACCOUNT_ID>:role/process-upload-role \
  --handler handler.lambda_handler \
  --zip-file fileb://function.zip \
  --timeout 30
```

Wire the S3 trigger — grant S3 permission to invoke the function, then configure the bucket notification:

```bash
aws lambda add-permission \
  --function-name process-upload \
  --statement-id s3-invoke \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn arn:aws:s3:::my-data-lab-2026 \
  --source-account <ACCOUNT_ID>

aws s3api put-bucket-notification-configuration \
  --bucket my-data-lab-2026 \
  --notification-configuration '{
    "LambdaFunctionConfigurations": [
      {
        "LambdaFunctionArn": "arn:aws:lambda:us-east-1:<ACCOUNT_ID>:function:process-upload",
        "Events": ["s3:ObjectCreated:*"]
      }
    ]
  }'
```

Test by uploading a file and checking the logs:

```bash
aws s3 cp test-object.txt s3://my-data-lab-2026/trigger-test.txt

aws logs tail /aws/lambda/process-upload --since 2m
```

## Lab 18.2 — API Gateway in Front of It, With IAM Auth

A separate HTTP-triggered function for this lab, since the S3-triggered one above isn't meant to be called directly. Save as `api_handler.py`:

```python
import json

def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "body": json.dumps({"message": "authenticated request received"})
    }
```

```bash
zip api_function.zip api_handler.py

# Reuse the same scoped-role pattern — this function only needs its own log group
aws iam create-role \
  --role-name api-handler-role \
  --assume-role-policy-document file://lambda-trust-policy.json

aws lambda create-function \
  --function-name api-handler \
  --runtime python3.12 \
  --role arn:aws:iam::<ACCOUNT_ID>:role/api-handler-role \
  --handler api_handler.lambda_handler \
  --zip-file fileb://api_function.zip
```

Create an HTTP API with **IAM authorization** — this means callers must sign requests with SigV4 (an IAM identity), which is generally the stronger option over an API key when both caller and callee are in AWS-managed identity space, since it ties access back to auditable IAM principals rather than a bearer string that can leak:

```bash
aws apigatewayv2 create-api \
  --name secure-api \
  --protocol-type HTTP \
  --target arn:aws:lambda:us-east-1:<ACCOUNT_ID>:function:api-handler

# Note the ApiId from the output, then set the route to require IAM auth
aws apigatewayv2 get-routes --api-id <API_ID>

aws apigatewayv2 update-route \
  --api-id <API_ID> \
  --route-id <ROUTE_ID> \
  --authorization-type AWS_IAM

# Allow API Gateway to invoke the function
aws lambda add-permission \
  --function-name api-handler \
  --statement-id apigw-invoke \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:us-east-1:<ACCOUNT_ID>:<API_ID>/*"
```

Test it — an unsigned request should be rejected, and a SigV4-signed one (via the CLI's built-in signing) should succeed:

```bash
# Unsigned — expect 403
curl -s -o /dev/null -w "%{http_code}\n" "<API_ENDPOINT>/"

# Signed with your IAM credentials — expect 200
curl -s -o /dev/null -w "%{http_code}\n" \
  --aws-sigv4 "aws:amz:us-east-1:execute-api" \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
  "<API_ENDPOINT>/"
```

If you specifically need external, non-AWS-identity callers (a third-party integration, a public-facing client), an **API key** is the more appropriate choice instead of IAM auth — it's simpler for callers outside your AWS account, but weaker (a leaked key is a leaked key, with no IAM audit trail behind it), so pair it with usage plans/throttling and treat the key itself as a secret per [12](../12-secrets-and-credential-management/README.md).

---

**Previous:** [17 — WAF, Shield & Incident Response Basics](../17-waf-shield-and-incident-response-basics/README.md)
**Next:** [19 — Infrastructure as Code](../19-infrastructure-as-code/README.md)
