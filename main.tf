data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# ------------------------------------------------------------------------------
# GuardDuty Detector
# ------------------------------------------------------------------------------
resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }

    kubernetes {
      audit_logs {
        enable = var.enable_eks_protection
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = var.tags
}

resource "aws_guardduty_detector_feature" "rds_login_events" {
  detector_id = aws_guardduty_detector.this.id
  name        = "RDS_LOGIN_EVENTS"
  status      = var.enable_rds_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "lambda_network_logs" {
  detector_id = aws_guardduty_detector.this.id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = var.enable_lambda_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.this.id
  name        = "RUNTIME_MONITORING"
  status      = var.enable_runtime_monitoring ? "ENABLED" : "DISABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = var.enable_runtime_monitoring ? "ENABLED" : "DISABLED"
  }

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = var.enable_runtime_monitoring ? "ENABLED" : "DISABLED"
  }

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = var.enable_runtime_monitoring ? "ENABLED" : "DISABLED"
  }
}

# ------------------------------------------------------------------------------
# GuardDuty Member Accounts
# ------------------------------------------------------------------------------
resource "aws_guardduty_member" "this" {
  for_each = { for m in var.member_accounts : m.account_id => m }

  detector_id                = aws_guardduty_detector.this.id
  account_id                 = each.value.account_id
  email                      = each.value.email
  invite                     = each.value.invite
  disable_email_notification = false
}

# ------------------------------------------------------------------------------
# GuardDuty Filters
# ------------------------------------------------------------------------------
resource "aws_guardduty_filter" "this" {
  for_each = { for f in var.filter_criteria : f.name => f }

  detector_id = aws_guardduty_detector.this.id
  name        = each.value.name
  description = each.value.description
  rank        = each.value.rank
  action      = each.value.action

  finding_criteria {
    dynamic "criterion" {
      for_each = each.value.criterion
      content {
        field                 = criterion.value.field
        equals                = criterion.value.equals
        not_equals            = criterion.value.not_equals
        greater_than          = criterion.value.greater_than
        greater_than_or_equal = criterion.value.greater_than_or_equal
        less_than             = criterion.value.less_than
        less_than_or_equal    = criterion.value.less_than_or_equal
      }
    }
  }

  tags = var.tags
}

# ------------------------------------------------------------------------------
# S3 Bucket for Findings Archive
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "findings" {
  bucket        = coalesce(var.publishing_destination_bucket, "${var.detector_name}-guardduty-findings-${data.aws_caller_identity.current.account_id}")
  force_destroy = false

  tags = merge(var.tags, {
    Purpose = "guardduty-findings-archive"
  })
}

resource "aws_s3_bucket_versioning" "findings" {
  bucket = aws_s3_bucket.findings.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  bucket = aws_s3_bucket.findings.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    id     = "archive-to-glacier"
    status = "Enabled"

    transition {
      days          = var.findings_archive_lifecycle_days
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_policy" "findings" {
  bucket = aws_s3_bucket.findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowGuardDutyGetBucketLocation"
        Effect    = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:GetBucketLocation"
        Resource  = aws_s3_bucket.findings.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "AllowGuardDutyPutObject"
        Effect    = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.findings.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.findings.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# GuardDuty Publishing Destination
# ------------------------------------------------------------------------------
resource "aws_guardduty_publishing_destination" "this" {
  detector_id     = aws_guardduty_detector.this.id
  destination_arn = aws_s3_bucket.findings.arn
  destination_type = "S3"

  depends_on = [aws_s3_bucket_policy.findings]
}

# ------------------------------------------------------------------------------
# Security Hub
# ------------------------------------------------------------------------------
resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0

  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"

  depends_on = [aws_guardduty_detector.this]
}

resource "aws_securityhub_product_subscription" "guardduty" {
  count = var.enable_security_hub ? 1 : 0

  product_arn = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::product/aws/guardduty"

  depends_on = [aws_securityhub_account.this]
}

# ------------------------------------------------------------------------------
# SNS Topic for Alerts
# ------------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = coalesce(var.sns_topic_name, "${var.detector_name}-guardduty-alerts")

  kms_master_key_id = "alias/aws/sns"

  tags = var.tags
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.alerts.arn
      },
      {
        Sid       = "AllowLambdaPublish"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# EventBridge Rule for GuardDuty Findings
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.detector_name}-guardduty-findings"
  description = "Capture GuardDuty findings for processing"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      title       = "$.detail.title"
      description = "$.detail.description"
      account     = "$.detail.accountId"
      region      = "$.detail.region"
      type        = "$.detail.type"
    }
    input_template = "\"GuardDuty Finding [Severity: <severity>] in account <account> (<region>): <title> - <description>\""
  }
}

resource "aws_cloudwatch_event_target" "lambda" {
  count = var.enable_ai_triage ? 1 : 0

  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = aws_lambda_function.ai_triage[0].arn
}

# ------------------------------------------------------------------------------
# AI Triage Lambda Function
# ------------------------------------------------------------------------------
resource "aws_iam_role" "ai_triage_lambda" {
  count = var.enable_ai_triage ? 1 : 0

  name = "${var.detector_name}-ai-triage-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ai_triage_basic" {
  count = var.enable_ai_triage ? 1 : 0

  role       = aws_iam_role.ai_triage_lambda[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "ai_triage_bedrock" {
  count = var.enable_ai_triage ? 1 : 0

  name = "${var.detector_name}-bedrock-invoke"
  role = aws_iam_role.ai_triage_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:bedrock:${data.aws_region.current.name}::foundation-model/${var.bedrock_model_id}"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ai_triage_sns" {
  count = var.enable_ai_triage ? 1 : 0

  name = "${var.detector_name}-sns-publish"
  role = aws_iam_role.ai_triage_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "ai_triage_guardduty" {
  count = var.enable_ai_triage ? 1 : 0

  name = "${var.detector_name}-guardduty-read"
  role = aws_iam_role.ai_triage_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "guardduty:GetDetector"
        ]
        Resource = [
          aws_guardduty_detector.this.arn,
          "${aws_guardduty_detector.this.arn}/*"
        ]
      }
    ]
  })
}

data "archive_file" "ai_triage" {
  count = var.enable_ai_triage ? 1 : 0

  type        = "zip"
  source_dir  = "${path.module}/lambdas"
  output_path = "${path.module}/.build/ai_triage.zip"
}

resource "aws_lambda_function" "ai_triage" {
  count = var.enable_ai_triage ? 1 : 0

  function_name = "${var.detector_name}-ai-triage"
  role          = aws_iam_role.ai_triage_lambda[0].arn
  runtime       = "python3.12"
  handler       = "ai_triage_handler.handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.ai_triage[0].output_path
  source_code_hash = data.archive_file.ai_triage[0].output_base64sha256

  environment {
    variables = {
      BEDROCK_MODEL_ID = var.bedrock_model_id
      SNS_TOPIC_ARN    = aws_sns_topic.alerts.arn
      DETECTOR_ID      = aws_guardduty_detector.this.id
    }
  }

  tags = var.tags
}

resource "aws_lambda_permission" "eventbridge" {
  count = var.enable_ai_triage ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ai_triage[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

# ------------------------------------------------------------------------------
# CloudWatch Log Group for Lambda
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "ai_triage" {
  count = var.enable_ai_triage ? 1 : 0

  name              = "/aws/lambda/${var.detector_name}-ai-triage"
  retention_in_days = var.lambda_log_retention_days

  tags = var.tags
}
