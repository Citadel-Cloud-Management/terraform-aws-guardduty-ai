# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-01

### Added

- Initial release of the terraform-aws-guardduty-ai module.
- GuardDuty detector with all protection plans configurable.
- Multi-account member support with invitations.
- Custom finding filters.
- S3 publishing destination with encryption and lifecycle rules.
- AWS Security Hub integration with GuardDuty product subscription.
- EventBridge rule for capturing GuardDuty findings.
- AI-powered triage Lambda function using Amazon Bedrock.
- SNS topic for alert notifications with KMS encryption.
- CloudWatch log group with configurable retention.
- Comprehensive IAM roles following least-privilege principles.

## [0.1.0] - 2024-10-15

### Added

- Pre-release module scaffolding.
- Basic GuardDuty detector and EventBridge rule.
