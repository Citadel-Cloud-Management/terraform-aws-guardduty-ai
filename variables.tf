variable "detector_name" {
  description = "Logical name used for naming related resources (IAM roles, Lambda functions, etc.)"
  type        = string
}

variable "enable_s3_protection" {
  description = "Enable S3 Protection for the GuardDuty detector"
  type        = bool
  default     = true
}

variable "enable_eks_protection" {
  description = "Enable EKS Audit Log Monitoring for the GuardDuty detector"
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  description = "Enable Malware Protection for EBS volumes"
  type        = bool
  default     = true
}

variable "enable_rds_protection" {
  description = "Enable RDS Login Activity Monitoring"
  type        = bool
  default     = true
}

variable "enable_lambda_protection" {
  description = "Enable Lambda Network Activity Monitoring"
  type        = bool
  default     = true
}

variable "enable_runtime_monitoring" {
  description = "Enable Runtime Monitoring for EC2, ECS, and EKS"
  type        = bool
  default     = true
}

variable "publishing_destination_bucket" {
  description = "Name of the S3 bucket for publishing GuardDuty findings. If empty, a bucket is created."
  type        = string
  default     = ""
}

variable "finding_publishing_frequency" {
  description = "Frequency of publishing updated findings (FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS)"
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "finding_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "filter_criteria" {
  description = "List of custom GuardDuty filter configurations"
  type = list(object({
    name        = string
    description = optional(string, "")
    rank        = optional(number, 1)
    action      = string # ARCHIVE or NOOP
    criterion = list(object({
      field                 = string
      equals                = optional(list(string))
      not_equals            = optional(list(string))
      greater_than          = optional(string)
      greater_than_or_equal = optional(string)
      less_than             = optional(string)
      less_than_or_equal    = optional(string)
    }))
  }))
  default = []
}

variable "enable_ai_triage" {
  description = "Enable AI-powered finding triage via Lambda and Bedrock"
  type        = bool
  default     = true
}

variable "bedrock_model_id" {
  description = "Bedrock foundation model ID for AI triage analysis"
  type        = string
  default     = "anthropic.claude-3-sonnet-20240229-v1:0"
}

variable "sns_topic_name" {
  description = "Name of the SNS topic for GuardDuty alerts"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Map of tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub and subscribe GuardDuty findings"
  type        = bool
  default     = true
}

variable "member_accounts" {
  description = "List of member account configurations for multi-account GuardDuty"
  type = list(object({
    account_id = string
    email      = string
    invite     = optional(bool, true)
  }))
  default = []
}

variable "lambda_log_retention_days" {
  description = "CloudWatch log retention period in days for the triage Lambda"
  type        = number
  default     = 30
}

variable "lambda_timeout" {
  description = "Timeout in seconds for the AI triage Lambda function"
  type        = number
  default     = 120
}

variable "lambda_memory_size" {
  description = "Memory in MB for the AI triage Lambda function"
  type        = number
  default     = 512
}

variable "findings_archive_lifecycle_days" {
  description = "Number of days before transitioning archived findings to Glacier"
  type        = number
  default     = 90
}
