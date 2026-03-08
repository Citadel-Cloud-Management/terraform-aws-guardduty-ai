output "detector_id" {
  description = "The ID of the GuardDuty detector"
  value       = aws_guardduty_detector.this.id
}

output "detector_arn" {
  description = "The ARN of the GuardDuty detector"
  value       = aws_guardduty_detector.this.arn
}

output "security_hub_arn" {
  description = "The ARN of the Security Hub account (if enabled)"
  value       = var.enable_security_hub ? aws_securityhub_account.this[0].arn : null
}

output "eventbridge_rule_arn" {
  description = "The ARN of the EventBridge rule for GuardDuty findings"
  value       = aws_cloudwatch_event_rule.guardduty_findings.arn
}

output "lambda_function_arn" {
  description = "The ARN of the AI triage Lambda function (if enabled)"
  value       = var.enable_ai_triage ? aws_lambda_function.ai_triage[0].arn : null
}

output "sns_topic_arn" {
  description = "The ARN of the SNS topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "s3_bucket_arn" {
  description = "The ARN of the S3 bucket for findings archive"
  value       = aws_s3_bucket.findings.arn
}

output "s3_bucket_name" {
  description = "The name of the S3 bucket for findings archive"
  value       = aws_s3_bucket.findings.id
}

output "lambda_role_arn" {
  description = "The ARN of the IAM role used by the triage Lambda"
  value       = var.enable_ai_triage ? aws_iam_role.ai_triage_lambda[0].arn : null
}

output "cloudwatch_log_group_name" {
  description = "The name of the CloudWatch log group for the triage Lambda"
  value       = var.enable_ai_triage ? aws_cloudwatch_log_group.ai_triage[0].name : null
}
