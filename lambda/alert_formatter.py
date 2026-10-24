"""
Alert Formatter Module
Formats detection results into human-readable email notifications.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


def format_alert(detection):
    """
    Format a detection result into an email subject and body.

    Args:
        detection (dict): Detection result from evaluate_event().

    Returns:
        dict: {"subject": str, "body": str} or None if formatting fails.
    """
    if not detection or not detection.get("matched"):
        logger.warning("No valid detection to format")
        return None

    try:
        event_details = detection.get("event_details", {})
        severity = detection.get("severity", "UNKNOWN")
        category = detection.get("category", "Unknown")
        rule_name = detection.get("rule_name", "Unknown")
        description = detection.get("description", "No description available.")
        recommendation = detection.get("recommendation", "Review the event in CloudTrail.")

        emoji = SEVERITY_EMOJI.get(severity, "⚪")

        # Build subject line
        subject = (
            f"{emoji} [{severity}] AWS Security Alert: {rule_name} "
            f"in {event_details.get('aws_region', 'unknown-region')}"
        )

        # Build body
        body = _build_alert_body(
            severity=severity,
            emoji=emoji,
            category=category,
            rule_name=rule_name,
            description=description,
            recommendation=recommendation,
            event_details=event_details,
        )

        logger.info("Formatted alert: subject=%s", subject)

        return {
            "subject": subject,
            "body": body,
        }

    except Exception as e:
        logger.error("Failed to format alert: %s", str(e))
        return None


def _build_alert_body(severity, emoji, category, rule_name, description,
                      recommendation, event_details):
    """Build the full alert email body."""

    alert_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    body = f"""
{'='*60}
{emoji} AWS SECURITY ALERT {emoji}
{'='*60}

ALERT SUMMARY
{'-'*40}
  Title:        {rule_name}
  Severity:     {severity} {emoji}
  Category:     {category}
  Alert Time:   {alert_time}

EVENT DETAILS
{'-'*40}
  Event Name:   {event_details.get('event_name', 'Unknown')}
  Event Time:   {event_details.get('event_time', 'Unknown')}
  AWS Region:   {event_details.get('aws_region', 'Unknown')}
  Event Source:  {event_details.get('event_source', 'Unknown')}
  Event ID:     {event_details.get('event_id', 'Unknown')}

IDENTITY INFORMATION
{'-'*40}
  User Type:    {event_details.get('user_type', 'Unknown')}
  Username:     {event_details.get('username', 'Unknown')}
  Account ID:   {event_details.get('account_id', 'Unknown')}
  Principal:    {event_details.get('principal_id', 'Unknown')}
  ARN:          {event_details.get('arn', 'Unknown')}
  Source IP:    {event_details.get('source_ip', 'Unknown')}
  Root User:    {'YES ⚠️' if event_details.get('is_root') else 'No'}

AFFECTED RESOURCE
{'-'*40}
  Resource:     {event_details.get('affected_resource', 'Unknown')}

DESCRIPTION
{'-'*40}
  {description}
"""

    # Add error information if present
    error_code = event_details.get('error_code')
    error_message = event_details.get('error_message')
    if error_code or error_message:
        body += f"""
ERROR INFORMATION
{'-'*40}
  Error Code:   {error_code or 'N/A'}
  Error Msg:    {error_message or 'N/A'}
"""

    body += f"""
RECOMMENDED ACTIONS
{'-'*40}
  {recommendation}

INVESTIGATION STEPS
{'-'*40}
  1. Review the event in AWS CloudTrail console.
  2. Identify who performed this action and whether it was authorized.
  3. Check related resources for additional changes.
  4. If unauthorized, follow your incident response procedures.
  5. Search CloudTrail for Event ID: {event_details.get('event_id', 'Unknown')}

{'='*60}
NOTE: This is an automated security notification.
An event is a potential security indicator, not proof
of malicious activity. Always investigate before
taking corrective action.
{'='*60}
"""

    return body