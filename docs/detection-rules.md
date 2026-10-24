# Detection Rules

## Severity Levels

| Severity | Emoji | Action Required |
|----------|-------|-----------------|
| CRITICAL | 🔴 | Immediate investigation. Potential active threat or misconfiguration. |
| HIGH | 🟠 | Prompt review. Sensitive security configuration modified. |
| MEDIUM | 🟡 | Review during routine security audit. |
| LOW | 🟢 | Informational event. |

## Category A: IAM Changes

| Event Name | Default Severity | Description |
|------------|-----------------|-------------|
| CreateUser | HIGH | New IAM user created |
| DeleteUser | HIGH | IAM user deleted |
| CreateAccessKey | HIGH | New access key generated |
| CreatePolicy / DeletePolicy | MEDIUM | Custom policy created or deleted |
| AttachUserPolicy / AttachRolePolicy | HIGH | Policy attached to user or role |
| PutUserPolicy / PutRolePolicy | HIGH | Inline policy added to user or role |

## Category B: EC2 Network Security

| Event Name | Default Severity | Description |
|------------|-----------------|-------------|
| AuthorizeSecurityGroupIngress | HIGH / CRITICAL* | Inbound security group rule added |
| RevokeSecurityGroupIngress | MEDIUM | Inbound security group rule removed |

*\*Elevated to CRITICAL when SSH (port 22) or RDP (port 3389) is exposed to `0.0.0.0/0` or `::/0`.*

## Category C: S3 Security

| Event Name | Default Severity | Description |
|------------|-----------------|-------------|
| PutBucketPolicy | HIGH | S3 bucket policy modified |
| DeleteBucketPublicAccessBlock | CRITICAL | Public access block removed from bucket |
| PutBucketAcl | HIGH | Bucket ACL changed |

## Category D: Authentication & Special Rules

| Event Name / Condition | Default Severity | Description |
|-----------------------|-----------------|-------------|
| ConsoleLogin (Failure) | HIGH | Failed console sign-in attempt |
| ConsoleLogin (Success) | LOW | Successful console sign-in |
| Root User Activity | CRITICAL | Any action performed by the AWS root user |