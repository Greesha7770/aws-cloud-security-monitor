output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.security_monitor.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.security_monitor.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic"
  value       = aws_sns_topic.security_alerts.name
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group for Lambda"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "important_notes" {
  description = "Post-deployment reminders"
  value       = <<-EOT

    ========================================
    IMPORTANT POST-DEPLOYMENT STEPS:
    ========================================
    1. CHECK YOUR EMAIL and confirm the SNS subscription.
       Look for an email from "AWS Notifications" with subject
       "AWS Notification - Subscription Confirmation"

    2. The system is now monitoring for security events.
    ========================================
  EOT
}