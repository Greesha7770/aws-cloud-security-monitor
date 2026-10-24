"""
AWS Lambda Handler
Main entry point for the security monitoring Lambda function.
Receives EventBridge events, evaluates them against detection rules,
and sends SNS notifications for matches.
"""

import json
import logging
import os

import boto3

from event_parser import parse_event, evaluate_event
from alert_formatter import format_alert

# Configure logging
log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger()
logger.setLevel(log_level)

# SNS client - initialized outside handler for connection reuse
sns_client = boto3.client("sns")

# SNS Topic ARN from environment variable
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")


def lambda_handler(event, context):
    """
    Lambda function entry point.

    Args:
        event (dict): EventBridge event payload.
        context: Lambda context object.

    Returns:
        dict: Response with statusCode and body.
    """
    logger.info("Received event: source=%s", event.get("source", "unknown"))
    logger.debug("Full event: %s", json.dumps(event, default=str))

    try:
        # Step 1: Parse the event
        parsed_event = parse_event(event)
        if not parsed_event:
            logger.info("Event could not be parsed or is not relevant. Skipping.")
            return _response(200, "Event skipped - not parseable")

        # Step 2: Evaluate against detection rules
        detection = evaluate_event(parsed_event)
        if not detection:
            logger.info(
                "Event '%s' did not match any detection rule. Skipping.",
                parsed_event.get("event_name", "Unknown")
            )
            return _response(200, "Event skipped - no rule match")

        # Step 3: Format the alert
        alert = format_alert(detection)
        if not alert:
            logger.error("Failed to format alert for detection: %s",
                        detection.get("rule_name", "Unknown"))
            return _response(500, "Alert formatting failed")

        # Step 4: Send SNS notification
        if not SNS_TOPIC_ARN:
            logger.error("SNS_TOPIC_ARN environment variable is not set")
            return _response(500, "SNS topic ARN not configured")

        send_result = _send_notification(alert["subject"], alert["body"])

        if send_result:
            logger.info(
                "Alert sent successfully: rule=%s severity=%s",
                detection.get("rule_name"), detection.get("severity")
            )
            return _response(200, "Alert sent successfully")
        else:
            logger.error("Failed to send SNS notification")
            return _response(500, "Failed to send notification")

    except Exception as e:
        logger.error("Unexpected error in lambda_handler: %s", str(e), exc_info=True)
        return _response(500, f"Internal error: {str(e)}")


def _send_notification(subject, body):
    """
    Send notification via SNS.

    Args:
        subject (str): Email subject (truncated to 100 chars for SNS).
        body (str): Email body.

    Returns:
        bool: True if sent successfully, False otherwise.
    """
    try:
        # SNS subject limit is 100 characters
        truncated_subject = subject[:100] if len(subject) > 100 else subject

        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=truncated_subject,
            Message=body,
        )

        message_id = response.get("MessageId", "Unknown")
        logger.info("SNS message published: MessageId=%s", message_id)
        return True

    except Exception as e:
        logger.error("Failed to publish to SNS: %s", str(e))
        return False


def _response(status_code, message):
    """Build a standard Lambda response."""
    return {
        "statusCode": status_code,
        "body": json.dumps({"message": message}),
    }