output "detector_id" {
  description = "The ID of the GuardDuty detector"
  value       = module.guardduty_ai.detector_id
}

output "detector_arn" {
  description = "The ARN of the GuardDuty detector"
  value       = module.guardduty_ai.detector_arn
}

output "lambda_function_arn" {
  description = "The ARN of the AI triage Lambda function"
  value       = module.guardduty_ai.lambda_function_arn
}

output "sns_topic_arn" {
  description = "The ARN of the SNS topic for alerts"
  value       = module.guardduty_ai.sns_topic_arn
}

output "s3_bucket_name" {
  description = "The name of the S3 bucket for findings archive"
  value       = module.guardduty_ai.s3_bucket_name
}

output "security_hub_arn" {
  description = "The ARN of the Security Hub account"
  value       = module.guardduty_ai.security_hub_arn
}
