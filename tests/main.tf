module "guardduty_ai" {
  source = "../"

  detector_name = "test-guardduty"

  enable_s3_protection       = true
  enable_eks_protection      = true
  enable_malware_protection  = true
  enable_rds_protection      = true
  enable_lambda_protection   = true
  enable_runtime_monitoring  = true

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  enable_ai_triage  = true
  bedrock_model_id  = "anthropic.claude-3-sonnet-20240229-v1:0"
  lambda_timeout    = 120
  lambda_memory_size = 512
  lambda_log_retention_days = 30

  enable_security_hub = false
  member_accounts     = []
  filter_criteria     = []

  findings_archive_lifecycle_days = 90

  tags = {
    Environment = "test"
    ManagedBy   = "terraform"
  }
}
