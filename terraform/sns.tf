# SNS Topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-alerts-${var.environment}"

  # Enable encryption at rest using AWS-managed KMS key
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name = "${var.project_name}-alerts"
  }
}

# SNS Topic Policy - restrict publish access to our Lambda function
resource "aws_sns_topic_policy" "security_alerts_policy" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "${var.project_name}-sns-policy"
    Statement = [
      {
        Sid       = "AllowLambdaPublish"
        Effect    = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_lambda_function.security_monitor.arn
          }
        }
      },
      {
        Sid       = "AllowAccountManagement"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "SNS:Subscribe",
          "SNS:SetTopicAttributes",
          "SNS:RemovePermission",
          "SNS:Publish",
          "SNS:ListSubscriptionsByTopic",
          "SNS:GetTopicAttributes",
          "SNS:DeleteTopic",
          "SNS:AddPermission"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# Email subscription
resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}