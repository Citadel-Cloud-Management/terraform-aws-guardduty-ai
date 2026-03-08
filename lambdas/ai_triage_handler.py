"""
GuardDuty AI Triage Lambda Handler

This Lambda function receives GuardDuty findings via EventBridge, sends them
to Amazon Bedrock for AI-powered threat analysis and triage, and publishes
enriched findings with remediation recommendations to SNS.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

bedrock_runtime = boto3.client("bedrock-runtime")
sns_client = boto3.client("sns")

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0"
)
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")


def handler(event, context):
    """
    Process a GuardDuty finding from EventBridge, analyze it with Bedrock,
    and publish an enriched alert to SNS.

    Args:
        event: EventBridge event containing a GuardDuty finding in detail
        context: Lambda context object

    Returns:
        dict: Summary of the processing result
    """
    logger.info("Received GuardDuty finding event: %s", json.dumps(event, default=str))

    detail = event.get("detail", {})
    finding_type = detail.get("type", "Unknown")
    severity = detail.get("severity", 0)
    title = detail.get("title", "No title")
    description = detail.get("description", "No description")
    account_id = detail.get("accountId", "Unknown")
    region = detail.get("region", "Unknown")
    resource_info = detail.get("resource", {})

    logger.info(
        "Finding: type=%s, severity=%s, title=%s",
        finding_type,
        severity,
        title,
    )

    # Build the analysis prompt
    prompt = build_analysis_prompt(
        finding_type=finding_type,
        severity=severity,
        title=title,
        description=description,
        account_id=account_id,
        region=region,
        resource_info=resource_info,
    )

    # Send to Bedrock for analysis
    try:
        ai_analysis = invoke_bedrock(prompt)
        logger.info("Bedrock analysis completed successfully")
    except Exception as e:
        logger.error("Failed to invoke Bedrock: %s", str(e), exc_info=True)
        ai_analysis = (
            f"AI analysis unavailable due to error: {str(e)}. "
            "Manual review recommended."
        )

    # Build enriched alert message
    enriched_message = build_enriched_alert(
        finding_type=finding_type,
        severity=severity,
        title=title,
        description=description,
        account_id=account_id,
        region=region,
        ai_analysis=ai_analysis,
    )

    # Publish to SNS
    if SNS_TOPIC_ARN:
        try:
            publish_to_sns(enriched_message, severity, finding_type)
            logger.info("Published enriched alert to SNS")
        except Exception as e:
            logger.error("Failed to publish to SNS: %s", str(e), exc_info=True)

    return {
        "statusCode": 200,
        "finding_type": finding_type,
        "severity": severity,
        "ai_analysis_available": "unavailable" not in ai_analysis.lower(),
    }


def build_analysis_prompt(
    finding_type, severity, title, description, account_id, region, resource_info
):
    """Build a structured prompt for Bedrock threat analysis."""
    resource_str = json.dumps(resource_info, indent=2, default=str)

    return f"""Analyze the following AWS GuardDuty security finding and provide:
1. A threat severity assessment (Critical/High/Medium/Low) with justification
2. Potential impact analysis
3. Whether this is likely a true positive or false positive, with reasoning
4. Specific remediation steps
5. Recommended AWS services or actions to mitigate the threat

GuardDuty Finding:
- Type: {finding_type}
- Severity Score: {severity}
- Title: {title}
- Description: {description}
- Account: {account_id}
- Region: {region}
- Affected Resource:
{resource_str}

Provide your analysis in a structured format suitable for a security operations team."""


def invoke_bedrock(prompt):
    """
    Invoke Amazon Bedrock with the analysis prompt.

    Args:
        prompt: The analysis prompt string

    Returns:
        str: The model's analysis response
    """
    request_body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2048,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }
    )

    response = bedrock_runtime.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=request_body,
    )

    response_body = json.loads(response["body"].read())
    return response_body.get("content", [{}])[0].get("text", "No analysis generated")


def build_enriched_alert(
    finding_type, severity, title, description, account_id, region, ai_analysis
):
    """Build a formatted alert message combining the finding and AI analysis."""
    severity_label = classify_severity(severity)

    return (
        f"{'=' * 60}\n"
        f"GUARDDUTY FINDING - AI-ENRICHED ALERT\n"
        f"{'=' * 60}\n"
        f"Severity: {severity_label} ({severity})\n"
        f"Type: {finding_type}\n"
        f"Title: {title}\n"
        f"Account: {account_id}\n"
        f"Region: {region}\n"
        f"\nDescription:\n{description}\n"
        f"\n{'─' * 60}\n"
        f"AI THREAT ANALYSIS\n"
        f"{'─' * 60}\n"
        f"{ai_analysis}\n"
        f"{'=' * 60}\n"
    )


def classify_severity(severity_score):
    """Convert numeric severity to label."""
    if severity_score >= 7.0:
        return "HIGH"
    elif severity_score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def publish_to_sns(message, severity, finding_type):
    """Publish the enriched alert to SNS."""
    severity_label = classify_severity(severity)
    subject = f"[{severity_label}] GuardDuty: {finding_type}"

    # SNS subject has a 100-character limit
    if len(subject) > 100:
        subject = subject[:97] + "..."

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message,
    )
