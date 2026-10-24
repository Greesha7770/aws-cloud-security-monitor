# Random suffix to ensure globally unique S3 bucket names
resource "random_id" "suffix" {
  byte_length = 4
}

# CloudTrail S3 Bucket (only if enable_cloudtrail is true)
resource "aws_s3_bucket" "cloudtrail_logs" {
  count         = var.enable_cloudtrail ? 1 : 0
  bucket        = "${var.project_name}-trail-logs-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name = "${var.project_name}-cloudtrail-logs"
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle rule to expire old logs after 90 days to minimize costs
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = 90
    }
  }
}

# CloudTrail Trail
resource "aws_cloudtrail" "main" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${var.project_name}-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs[0].id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true

  # Write-only management events to keep costs low/free tier friendly
  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_bucket_policy
  ]

  tags = {
    Name = "${var.project_name}-trail"
  }
}