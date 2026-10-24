# =====================================================
# EventBridge Rules for Security Monitoring
# =====================================================

# Rule 1: IAM Changes
resource "aws_cloudwatch_event_rule" "iam_changes" {
  name        = "${var.project_name}-iam-changes-${var.environment}"
  description = "Detect IAM user, policy, and role changes"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "CreateUser",
        "DeleteUser",
        "CreateAccessKey",
        "CreatePolicy",
        "DeletePolicy",
        "CreatePolicyVersion",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy"
      ]
    }
  })

  tags = {
    Name     = "${var.project_name}-iam-changes"
    Category = "IAM"
  }
}

resource "aws_cloudwatch_event_target" "iam_changes_lambda" {
  rule      = aws_cloudwatch_event_rule.iam_changes.name
  target_id = "SecurityMonitorLambda"
  arn       = aws_lambda_function.security_monitor.arn
}

# Rule 2: EC2 Security Group Changes
resource "aws_cloudwatch_event_rule" "ec2_security_changes" {
  name        = "${var.project_name}-ec2-sg-changes-${var.environment}"
  description = "Detect security group ingress and egress rule changes"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupEgress"
      ]
    }
  })

  tags = {
    Name     = "${var.project_name}-ec2-sg-changes"
    Category = "EC2"
  }
}

resource "aws_cloudwatch_event_target" "ec2_changes_lambda" {
  rule      = aws_cloudwatch_event_rule.ec2_security_changes.name
  target_id = "SecurityMonitorLambda"
  arn       = aws_lambda_function.security_monitor.arn
}

# Rule 3: S3 Security Configuration Changes
resource "aws_cloudwatch_event_rule" "s3_security_changes" {
  name        = "${var.project_name}-s3-security-changes-${var.environment}"
  description = "Detect S3 bucket policy and public access changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketAcl"
      ]
    }
  })

  tags = {
    Name     = "${var.project_name}-s3-security-changes"
    Category = "S3"
  }
}

resource "aws_cloudwatch_event_target" "s3_changes_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_security_changes.name
  target_id = "SecurityMonitorLambda"
  arn       = aws_lambda_function.security_monitor.arn
}

# Rule 4: Console Sign-In Events
resource "aws_cloudwatch_event_rule" "console_signin" {
  name        = "${var.project_name}-console-signin-${var.environment}"
  description = "Detect AWS Console sign-in events including failures"

  event_pattern = jsonencode({
    source      = ["aws.signin"]
    detail-type = ["AWS Console Sign In via CloudTrail"]
    detail = {
      eventSource = ["signin.amazonaws.com"]
      eventName   = ["ConsoleLogin"]
    }
  })

  tags = {
    Name     = "${var.project_name}-console-signin"
    Category = "Authentication"
  }
}

resource "aws_cloudwatch_event_target" "signin_lambda" {
  rule      = aws_cloudwatch_event_rule.console_signin.name
  target_id = "SecurityMonitorLambda"
  arn       = aws_lambda_function.security_monitor.arn
}