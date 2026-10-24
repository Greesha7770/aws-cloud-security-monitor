"""
Tests for the event_parser module.
Tests cover all detection categories: IAM, EC2 Security Groups, S3, and Authentication.
"""

import pytest
import sys
import os

# Add lambda directory to path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from event_parser import parse_event, evaluate_event, _sanitize_params


class TestParseEvent:
    """Tests for the parse_event function."""

    def test_parse_create_user_event(self, sample_create_user_event):
        """Test parsing a valid CreateUser event."""
        result = parse_event(sample_create_user_event)

        assert result is not None
        assert result["event_name"] == "CreateUser"
        assert result["event_source"] == "iam.amazonaws.com"
        assert result["aws_region"] == "us-east-1"
        assert result["username"] == "admin-user"
        assert result["source_ip"] == "203.0.113.50"
        assert result["event_id"] == "abcd1234-abcd-1234-abcd-123456789012"
        assert result["affected_resource"] == "new-test-user"
        assert result["is_root"] is False
        assert result["account_id"] == "123456789012"

    def test_parse_delete_user_event(self, sample_delete_user_event):
        """Test parsing a valid DeleteUser event."""
        result = parse_event(sample_delete_user_event)

        assert result is not None
        assert result["event_name"] == "DeleteUser"
        assert result["affected_resource"] == "old-test-user"

    def test_parse_create_access_key_event(self, sample_create_access_key_event):
        """Test parsing CreateAccessKey event with secret redaction."""
        result = parse_event(sample_create_access_key_event)

        assert result is not None
        assert result["event_name"] == "CreateAccessKey"
        response = result.get("response_elements", {})
        access_key = response.get("accessKey", {})
        assert access_key.get("secretAccessKey") == "[REDACTED]"

    def test_parse_security_group_event(self, sample_security_group_open_ssh_event):
        """Test parsing a security group ingress event."""
        result = parse_event(sample_security_group_open_ssh_event)

        assert result is not None
        assert result["event_name"] == "AuthorizeSecurityGroupIngress"
        assert result["event_source"] == "ec2.amazonaws.com"
        assert result["affected_resource"] == "sg-0123456789abcdef0"

    def test_parse_s3_bucket_policy_event(self, sample_put_bucket_policy_event):
        """Test parsing an S3 PutBucketPolicy event."""
        result = parse_event(sample_put_bucket_policy_event)

        assert result is not None
        assert result["event_name"] == "PutBucketPolicy"
        assert result["event_source"] == "s3.amazonaws.com"
        assert result["affected_resource"] == "my-sensitive-bucket"

    def test_parse_console_login_failure(self, sample_console_login_failure_event):
        """Test parsing a failed console login event."""
        result = parse_event(sample_console_login_failure_event)

        assert result is not None
        assert result["event_name"] == "ConsoleLogin"
        assert result["error_message"] == "Failed authentication"
        assert result["username"] == "test-user"
        assert result["source_ip"] == "198.51.100.42"

    def test_parse_root_user_event(self, sample_root_user_event):
        """Test parsing a root user event."""
        result = parse_event(sample_root_user_event)

        assert result is not None
        assert result["is_root"] is True
        assert result["username"] == "ROOT"
        assert result["user_type"] == "Root"

    def test_parse_malformed_no_detail(self, malformed_event_no_detail):
        """Test parsing an event with no detail field."""
        result = parse_event(malformed_event_no_detail)
        assert result is None

    def test_parse_malformed_empty(self, malformed_event_empty):
        """Test parsing an empty event."""
        result = parse_event(malformed_event_empty)
        assert result is None

    def test_parse_malformed_not_dict(self, malformed_event_not_dict):
        """Test parsing a non-dict event."""
        result = parse_event(malformed_event_not_dict)
        assert result is None

    def test_parse_none_event(self):
        """Test parsing None."""
        result = parse_event(None)
        assert result is None


class TestEvaluateEvent:
    """Tests for the evaluate_event function."""

    def test_evaluate_create_user(self, sample_create_user_event):
        """Test that CreateUser triggers HIGH severity IAM alert."""
        parsed = parse_event(sample_create_user_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["matched"] is True
        assert detection["rule_name"] == "CreateUser"
        assert detection["category"] == "IAM Changes"
        assert detection["severity"] == "HIGH"
        assert "IAM user was created" in detection["description"]

    def test_evaluate_delete_user(self, sample_delete_user_event):
        """Test that DeleteUser triggers HIGH severity alert."""
        parsed = parse_event(sample_delete_user_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["matched"] is True
        assert detection["severity"] == "HIGH"
        assert detection["category"] == "IAM Changes"

    def test_evaluate_create_access_key(self, sample_create_access_key_event):
        """Test that CreateAccessKey triggers HIGH severity alert."""
        parsed = parse_event(sample_create_access_key_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "HIGH"

    def test_evaluate_attach_user_policy(self, sample_attach_user_policy_event):
        """Test that AttachUserPolicy triggers HIGH severity alert."""
        parsed = parse_event(sample_attach_user_policy_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "HIGH"

    def test_evaluate_security_group_open_ssh(self, sample_security_group_open_ssh_event):
        """Test that SSH open to 0.0.0.0/0 triggers CRITICAL alert."""
        parsed = parse_event(sample_security_group_open_ssh_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "CRITICAL"
        assert "SSH" in detection["description"]
        assert "0.0.0.0/0" in detection["description"]

    def test_evaluate_security_group_open_rdp_ipv6(self, sample_security_group_open_rdp_ipv6_event):
        """Test that RDP open to ::/0 (IPv6) triggers CRITICAL alert."""
        parsed = parse_event(sample_security_group_open_rdp_ipv6_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "CRITICAL"
        assert "RDP" in detection["description"]
        assert "::/0" in detection["description"]

    def test_evaluate_security_group_safe_rule(self, sample_security_group_safe_event):
        """Test that a safe security group rule triggers HIGH (not CRITICAL)."""
        parsed = parse_event(sample_security_group_safe_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "HIGH"
        assert "DANGEROUS" not in detection["description"]

    def test_evaluate_s3_bucket_policy(self, sample_put_bucket_policy_event):
        """Test that PutBucketPolicy triggers HIGH alert."""
        parsed = parse_event(sample_put_bucket_policy_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "HIGH"

    def test_evaluate_s3_delete_public_access_block(self, sample_delete_public_access_block_event):
        """Test that DeleteBucketPublicAccessBlock triggers CRITICAL alert."""
        parsed = parse_event(sample_delete_public_access_block_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "CRITICAL"

    def test_evaluate_console_login_failure(self, sample_console_login_failure_event):
        """Test that failed console login triggers HIGH alert."""
        parsed = parse_event(sample_console_login_failure_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "HIGH"

    def test_evaluate_console_login_success(self, sample_console_login_success_event):
        """Test that successful console login triggers LOW alert."""
        parsed = parse_event(sample_console_login_success_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "LOW"

    def test_evaluate_root_user_escalates_severity(self, sample_root_user_event):
        """Test that root user activity escalates severity to CRITICAL."""
        parsed = parse_event(sample_root_user_event)
        detection = evaluate_event(parsed)

        assert detection is not None
        assert detection["severity"] == "CRITICAL"

    def test_evaluate_unrelated_event_no_match(self, sample_unrelated_event):
        """Test that unrelated events do not trigger alerts."""
        parsed = parse_event(sample_unrelated_event)
        detection = evaluate_event(parsed)

        assert detection is None


class TestSanitizeParams:
    """Tests for parameter sanitization."""

    def test_sanitize_removes_secrets(self):
        """Test that sensitive fields are redacted."""
        params = {
            "userName": "test-user",
            "password": "super-secret-123",
            "secretAccessKey": "AKIAXXXXXXXXXXXXXX",
            "normalField": "visible",
        }
        result = _sanitize_params(params)

        assert result["userName"] == "test-user"
        assert result["password"] == "[REDACTED]"
        assert result["secretAccessKey"] == "[REDACTED]"
        assert result["normalField"] == "visible"