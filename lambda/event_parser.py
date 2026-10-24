"""
Event Parser Module
Parses AWS EventBridge events from CloudTrail and extracts security-relevant details.
"""

import logging

logger = logging.getLogger(__name__)

# Mapping of event names to detection categories and severity
DETECTION_RULES = {
    # IAM Changes - Category A
    "CreateUser": {
        "category": "IAM Changes",
        "severity": "HIGH",
        "description": "A new IAM user was created.",
        "recommendation": "Verify this user creation was authorized. Review the user's permissions and ensure MFA is enabled."
    },
    "DeleteUser": {
        "category": "IAM Changes",
        "severity": "HIGH",
        "description": "An IAM user was deleted.",
        "recommendation": "Confirm this deletion was intentional. Check if associated resources or access keys were properly cleaned up."
    },
    "CreateAccessKey": {
        "category": "IAM Changes",
        "severity": "HIGH",
        "description": "A new IAM access key was created.",
        "recommendation": "Verify this access key creation was authorized. Ensure it follows key rotation policies. Never expose access keys."
    },
    "CreatePolicy": {
        "category": "IAM Changes",
        "severity": "MEDIUM",
        "description": "A new IAM policy was created.",
        "recommendation": "Review the policy document for overly permissive permissions. Follow least-privilege principles."
    },
    "DeletePolicy": {
        "category": "IAM Changes",
        "severity": "MEDIUM",
        "description": "An IAM policy was deleted.",
        "recommendation": "Confirm this deletion was intentional and that no resources depend on this policy."
    },
    "CreatePolicyVersion": {
        "category": "IAM Changes",
        "severity": "MEDIUM",
        "description": "An IAM policy version was updated.",
        "recommendation": "Review the updated policy for permission changes. Ensure no privilege escalation occurred."
    },
    "AttachUserPolicy": {
        "category": "IAM Changes",
        "severity": "HIGH",
        "description": "A policy was attached to an IAM user.",
        "recommendation": "Verify the attached policy follows least-privilege. Prefer attaching policies to groups or roles instead."
    },
    "DetachUserPolicy": {
        "category": "IAM Changes",
        "severity": "MEDIUM",
        "description": "A policy was detached from an IAM user.",
        "recommendation": "Confirm this change was authorized and does not disrupt required access."
    },
    "AttachRolePolicy": {
        "category": "IAM Changes",
        "severity": "HIGH",
        "description": "A policy was attached to an IAM role.",
        "recommendation": "Review the role and attached policy. Ensure no privilege escalation or overly broad permissions."
    },
    "DetachRolePolicy": {
        "category": "IAM Changes",
        "severity": "MEDIUM",
        "description": "A policy was detached from an IAM role.",
        "recommendation": "Confirm this change was authorized and does not break dependent services."
    },
    "AttachGroupPolicy": {
        "category": "IAM Changes",
        "severity": "HIGH",
        "description": "A policy was attached to an IAM group.",
        "recommendation": "Review the group membership and attached policy permissions."
    },
    "DetachGroupPolicy": {
        "category": "IAM Changes",
        "severity": "MEDIUM",
        "description": "A policy was detached from an IAM group.",
        "recommendation": "Confirm this change was authorized."
    },
    "PutUserPolicy": {
        "category": "IAM Changes",
        "severity": "HIGH",
        "description": "An inline policy was added or updated on an IAM user.",
        "recommendation": "Review the inline policy. Prefer managed policies for better visibility and reuse."
    },
    "PutRolePolicy": {
        "category": "IAM Changes",
        "severity": "HIGH",
        "description": "An inline policy was added or updated on an IAM role.",
        "recommendation": "Review the inline policy document for overly permissive access."
    },

    # EC2 Network Security - Category B
    "AuthorizeSecurityGroupIngress": {
        "category": "EC2 Network Security",
        "severity": "HIGH",
        "description": "An inbound rule was added to a security group.",
        "recommendation": "Check if the rule exposes sensitive ports (SSH/RDP) to the internet (0.0.0.0/0 or ::/0). Restrict access to specific IPs."
    },
    "RevokeSecurityGroupIngress": {
        "category": "EC2 Network Security",
        "severity": "MEDIUM",
        "description": "An inbound rule was removed from a security group.",
        "recommendation": "Verify this change was intentional and does not disrupt required connectivity."
    },
    "AuthorizeSecurityGroupEgress": {
        "category": "EC2 Network Security",
        "severity": "MEDIUM",
        "description": "An outbound rule was added to a security group.",
        "recommendation": "Review the outbound rule for data exfiltration risks."
    },
    "RevokeSecurityGroupEgress": {
        "category": "EC2 Network Security",
        "severity": "LOW",
        "description": "An outbound rule was removed from a security group.",
        "recommendation": "Verify this change was intentional."
    },

    # S3 Security - Category C
    "PutBucketPolicy": {
        "category": "S3 Security",
        "severity": "HIGH",
        "description": "An S3 bucket policy was created or modified.",
        "recommendation": "Review the bucket policy for public access or overly permissive principals. Use AWS Policy Simulator to validate."
    },
    "DeleteBucketPolicy": {
        "category": "S3 Security",
        "severity": "MEDIUM",
        "description": "An S3 bucket policy was deleted.",
        "recommendation": "Verify this change was intentional. The bucket now relies on ACLs and public access block settings only."
    },
    "PutBucketPublicAccessBlock": {
        "category": "S3 Security",
        "severity": "HIGH",
        "description": "S3 bucket public access block settings were modified.",
        "recommendation": "Verify all four public access block settings are enabled unless there is a documented business need."
    },
    "DeleteBucketPublicAccessBlock": {
        "category": "S3 Security",
        "severity": "CRITICAL",
        "description": "S3 bucket public access block was removed.",
        "recommendation": "URGENT: Re-enable public access block immediately unless there is explicit authorization. This may expose the bucket publicly."
    },
    "PutBucketAcl": {
        "category": "S3 Security",
        "severity": "HIGH",
        "description": "An S3 bucket ACL was modified.",
        "recommendation": "Review the ACL for public access grants. AWS recommends disabling ACLs and using bucket policies instead."
    },

    # Authentication - Category D
    "ConsoleLogin": {
        "category": "Authentication",
        "severity": "MEDIUM",
        "description": "An AWS Management Console sign-in event was detected.",
        "recommendation": "If this was a failed login, investigate potential unauthorized access attempts. Verify MFA is enabled."
    },
}

# Events that indicate root user activity regardless of event name
ROOT_ACTIVITY_EVENTS = [
    "ConsoleLogin",
    "CreateAccessKey",
    "CreateUser",
]


def parse_event(event):
    """
    Parse an EventBridge event wrapping a CloudTrail event.

    Args:
        event (dict): The EventBridge event payload.

    Returns:
        dict: Parsed event details, or None if the event cannot be parsed.
    """
    if not isinstance(event, dict):
        logger.error("Event is not a dictionary: %s", type(event))
        return None

    try:
        detail = event.get("detail", {})
        if not detail:
            logger.warning("Event has no 'detail' field")
            return None

        event_name = detail.get("eventName", "Unknown")
        event_source = detail.get("eventSource", "Unknown")
        event_time = detail.get("eventTime", "Unknown")
        aws_region = detail.get("awsRegion", event.get("region", "Unknown"))
        event_id = detail.get("eventID", "Unknown")

        # Extract user identity information
        user_identity = detail.get("userIdentity", {})
        principal_id = user_identity.get("principalId", "Unknown")
        user_type = user_identity.get("type", "Unknown")
        arn = user_identity.get("arn", "Unknown")
        account_id = user_identity.get("accountId", "Unknown")
        username = _extract_username(user_identity)

        # Source IP
        source_ip = detail.get("sourceIPAddress", "Unknown")

        # Error information (for failed events)
        error_code = detail.get("errorCode", None)
        error_message = detail.get("errorMessage", None)

        # Request parameters (sanitized)
        request_params = detail.get("requestParameters", {}) or {}

        # Response elements (for resource identification)
        response_elements = detail.get("responseElements", {}) or {}

        # Determine if this is a root user action
        is_root = _is_root_user(user_identity)

        # Determine affected resource
        affected_resource = _extract_affected_resource(
            event_name, event_source, request_params, response_elements
        )

        parsed = {
            "event_name": event_name,
            "event_source": event_source,
            "event_time": event_time,
            "aws_region": aws_region,
            "event_id": event_id,
            "principal_id": principal_id,
            "user_type": user_type,
            "arn": _sanitize_arn(arn),
            "account_id": account_id,
            "username": username,
            "source_ip": source_ip,
            "error_code": error_code,
            "error_message": error_message,
            "is_root": is_root,
            "affected_resource": affected_resource,
            "request_parameters": _sanitize_params(request_params),
            "response_elements": _sanitize_params(response_elements),
            "raw_detail": detail,
        }

        logger.info(
            "Parsed event: name=%s source=%s region=%s user=%s",
            event_name, event_source, aws_region, username
        )

        return parsed

    except Exception as e:
        logger.error("Failed to parse event: %s", str(e))
        return None


def evaluate_event(parsed_event):
    """
    Evaluate a parsed event against detection rules.

    Args:
        parsed_event (dict): The parsed event from parse_event().

    Returns:
        dict: Detection result with rule info, or None if no rule matches.
    """
    if not parsed_event:
        return None

    event_name = parsed_event.get("event_name", "Unknown")

    # Check if event matches a detection rule
    rule = DETECTION_RULES.get(event_name)
    if not rule:
        logger.info("No detection rule for event: %s", event_name)
        return None

    # Build detection result
    severity = rule["severity"]
    category = rule["category"]
    description = rule["description"]
    recommendation = rule["recommendation"]

    # Elevate severity for root user activity
    if parsed_event.get("is_root", False):
        severity = "CRITICAL"
        description = f"[ROOT USER] {description}"
        recommendation = (
            f"ROOT USER ACTIVITY DETECTED. {recommendation} "
            "Root user access should be avoided for daily operations. "
            "Use IAM users or roles instead."
        )

    # Special handling for ConsoleLogin failures
    if event_name == "ConsoleLogin":
        response = parsed_event.get("response_elements", {})
        console_login_result = response.get("ConsoleLogin", "Unknown")
        error_code = parsed_event.get("error_code")

        if console_login_result == "Failure" or error_code:
            severity = "HIGH"
            description = "A failed AWS Console sign-in attempt was detected."
            recommendation = (
                "Investigate the source IP and identity. Multiple failed attempts "
                "may indicate a brute-force attack. Ensure MFA is enabled for all users."
            )
        elif console_login_result == "Success" and not parsed_event.get("is_root"):
            severity = "LOW"
            description = "A successful AWS Console sign-in was detected."
            recommendation = "Verify this sign-in was expected."

    # Special handling for security group rules - check for open access
    if event_name == "AuthorizeSecurityGroupIngress":
        sg_analysis = _analyze_security_group_rule(parsed_event)
        if sg_analysis:
            severity = sg_analysis.get("severity", severity)
            description = sg_analysis.get("description", description)
            recommendation = sg_analysis.get("recommendation", recommendation)

    detection = {
        "matched": True,
        "rule_name": event_name,
        "category": category,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "event_details": parsed_event,
    }

    logger.info(
        "Detection match: rule=%s category=%s severity=%s",
        event_name, category, severity
    )

    return detection


def _extract_username(user_identity):
    """Extract human-readable username from user identity."""
    if not user_identity:
        return "Unknown"

    user_type = user_identity.get("type", "")

    if user_type == "Root":
        return "ROOT"
    elif user_type == "IAMUser":
        return user_identity.get("userName", "Unknown")
    elif user_type == "AssumedRole":
        session_context = user_identity.get("sessionContext", {})
        session_issuer = session_context.get("sessionIssuer", {})
        role_name = session_issuer.get("userName", "")
        if role_name:
            return f"Role:{role_name}"
        arn = user_identity.get("arn", "")
        if "/" in arn:
            return arn.split("/")[-1]
        return "AssumedRole"
    elif user_type == "AWSService":
        invoking = user_identity.get("invokedBy", "Unknown")
        return f"Service:{invoking}"
    else:
        return user_identity.get("userName",
               user_identity.get("principalId", "Unknown"))


def _is_root_user(user_identity):
    """Determine if the action was performed by the root user."""
    if not user_identity:
        return False

    user_type = user_identity.get("type", "")
    if user_type == "Root":
        return True

    arn = user_identity.get("arn", "")
    if arn and ":root" in arn:
        return True

    return False


def _extract_affected_resource(event_name, event_source, request_params, response_elements):
    """Extract the affected resource identifier from event details."""
    resource = "Unknown"

    try:
        if "iam" in event_source.lower():
            resource = (
                request_params.get("userName")
                or request_params.get("policyArn")
                or request_params.get("roleName")
                or request_params.get("groupName")
                or request_params.get("policyName")
                or "IAM Resource"
            )
        elif "ec2" in event_source.lower():
            resource = (
                request_params.get("groupId")
                or request_params.get("securityGroupId")
                or "Security Group"
            )
        elif "s3" in event_source.lower():
            resource = (
                request_params.get("bucketName")
                or request_params.get("bucket")
                or "S3 Bucket"
            )
        elif "signin" in event_source.lower():
            resource = "AWS Console"
    except Exception as e:
        logger.warning("Could not extract affected resource: %s", str(e))

    return resource


def _sanitize_arn(arn):
    """Remove potentially sensitive details from ARN for logging."""
    if not arn or arn == "Unknown":
        return arn
    return str(arn)


def _sanitize_params(params):
    """Remove sensitive fields from request/response parameters."""
    if not params or not isinstance(params, dict):
        return {}

    sensitive_keys = {
        "password", "secretAccessKey", "sessionToken", "privateKey",
        "credentials", "accessKeySecret", "secret", "token",
        "oldPassword", "newPassword",
    }

    sanitized = {}
    for key, value in params.items():
        if key.lower() in {k.lower() for k in sensitive_keys}:
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_params(value)
        else:
            sanitized[key] = value

    return sanitized


def _analyze_security_group_rule(parsed_event):
    """
    Analyze security group ingress rules for dangerous patterns.
    Checks for SSH (22) or RDP (3389) open to 0.0.0.0/0 or ::/0.
    """
    request_params = parsed_event.get("request_parameters", {})

    ip_permissions = request_params.get("ipPermissions", {})
    items = ip_permissions.get("items", [])

    if not items:
        return None

    dangerous_ports = {22: "SSH", 3389: "RDP"}
    open_cidrs = {"0.0.0.0/0", "::/0"}

    findings = []

    for item in items:
        from_port = item.get("fromPort", 0)
        to_port = item.get("toPort", 0)

        # Check IPv4 ranges
        ip_ranges = item.get("ipRanges", {}).get("items", [])
        for ip_range in ip_ranges:
            cidr = ip_range.get("cidrIp", "")
            if cidr in open_cidrs:
                for port, service in dangerous_ports.items():
                    if from_port <= port <= to_port:
                        findings.append(f"{service} (port {port}) open to {cidr}")

        # Check IPv6 ranges
        ipv6_ranges = item.get("ipv6Ranges", {}).get("items", [])
        for ipv6_range in ipv6_ranges:
            cidr = ipv6_range.get("cidrIpv6", "")
            if cidr in open_cidrs:
                for port, service in dangerous_ports.items():
                    if from_port <= port <= to_port:
                        findings.append(f"{service} (port {port}) open to {cidr}")

    if findings:
        finding_text = "; ".join(findings)
        return {
            "severity": "CRITICAL",
            "description": (
                f"DANGEROUS: Security group rule allows unrestricted access. "
                f"Findings: {finding_text}"
            ),
            "recommendation": (
                "IMMEDIATELY restrict these security group rules to specific IP addresses. "
                "Open SSH/RDP to the internet is a critical security risk. "
                "Use a bastion host, VPN, or AWS Systems Manager Session Manager instead."
            ),
        }

    return None