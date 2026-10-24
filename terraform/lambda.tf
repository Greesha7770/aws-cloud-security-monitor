# Package the Lambda function code into a zip file automatically
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/lambda_function.zip"

  excludes = [
    "tests",
    "tests/*",
    "__pycache__",
    "__pycache__/*",
    "*.pyc",
    ".pytest_cache",
    ".pytest_cache/*",
    "requirements.txt",
  ]
}

# Lambda function definition
resource "aws_lambda_function" "security_monitor" {
  function_name    = "${var.project_name}-handler-${var.environment}"
  description      = "Processes CloudTrail security events and sends SNS alerts"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory
  role             = aws_iam_role.lambda_role.arn

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      LOG_LEVEL     = var.lambda_log_level
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy.lambda_logging,
    aws_iam_role_policy.lambda_sns,
  ]

  tags = {
    Name = "${var.project_name}-handler"
  }
}

# CloudWatch Log Group with log retention
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}-handler-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-lambda-logs"
  }
}

# Grant EventBridge permissions to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge_iam" {
  statement_id  = "AllowEventBridgeInvokeIAM"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_changes.arn
}

resource "aws_lambda_permission" "allow_eventbridge_ec2" {
  statement_id  = "AllowEventBridgeInvokeEC2"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ec2_security_changes.arn
}

resource "aws_lambda_permission" "allow_eventbridge_s3" {
  statement_id  = "AllowEventBridgeInvokeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_security_changes.arn
}

resource "aws_lambda_permission" "allow_eventbridge_signin" {
  statement_id  = "AllowEventBridgeInvokeSignIn"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_monitor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.console_signin.arn
}