variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "cloud-security-monitor"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "alert_email" {
  description = "Email address to receive security alerts"
  type        = string
  sensitive   = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 14
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "lambda_memory" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 128
}

variable "lambda_log_level" {
  description = "Lambda function log level"
  type        = string
  default     = "INFO"
}

variable "enable_cloudtrail" {
  description = "Whether to create a CloudTrail trail"
  type        = bool
  default     = true
}