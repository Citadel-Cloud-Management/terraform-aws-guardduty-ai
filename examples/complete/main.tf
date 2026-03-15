################################################################################
# GuardDuty AI - Complete Example
################################################################################

module "guardduty_ai" {
  source = "../../"

  detector_name = "org-guardduty-detector"

  # Enable all protection features
  enable_s3_protection      = true
  enable_eks_protection     = true
  enable_malware_protection = true
  enable_rds_protection     = true
  enable_lambda_protection  = true
  enable_runtime_monitoring = true

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  # AI triage configuration
  enable_ai_triage           = true
  bedrock_model_id           = "anthropic.claude-3-sonnet-20240229-v1:0"
  lambda_timeout             = 120
  lambda_memory_size         = 512
  lambda_log_retention_days  = 90

  # Security Hub integration
  enable_security_hub = true

  # Custom filter to auto-archive low-severity DNS findings
  filter_criteria = [
    {
      name        = "archive-low-severity-dns"
      description = "Auto-archive low severity DNS data exfiltration findings"
      rank        = 1
      action      = "ARCHIVE"
      criterion = [
        {
          field  = "severity"
          less_than = "4"
        },
        {
          field  = "type"
          equals = ["Trojan:EC2/DNSDataExfiltration"]
        }
      ]
    }
  ]

  # Multi-account setup
  member_accounts = [
    {
      account_id = "111111111111"
      email      = "security-dev@example.com"
      invite     = true
    },
    {
      account_id = "222222222222"
      email      = "security-staging@example.com"
      invite     = true
    }
  ]

  findings_archive_lifecycle_days = 90

  tags = {
    Project     = "security-operations"
    Environment = "production"
    Team        = "security"
    Compliance  = "soc2"
  }
}
