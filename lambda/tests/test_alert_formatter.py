"""
Tests for the alert_formatter module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from event_parser import parse_event, evaluate_event
from alert_formatter import format_alert


class TestFormatAlert:
    """Tests for the format_alert function."""

    def test_format_iam_create_user_alert(self, sample_create_user_event):
        """Test formatting a CreateUser alert."""
        parsed = parse_event(sample_create_user_event)
        detection = evaluate_event(parsed)
        alert = format_alert(detection)

        assert alert is not None
        assert "subject" in alert
        assert "body" in alert
        assert "CreateUser" in alert["subject"]
        assert "HIGH" in alert["subject"]

        body = alert["body"]
        assert "CreateUser" in body
        assert "admin-user" in body
        assert "us-east-1" in body
        assert "203.0.113.50" in body

    def test_format_critical_security_group_alert(self, sample_security_group_open_ssh_event):
        """Test formatting a CRITICAL security group alert."""
        parsed = parse_event(sample_security_group_open_ssh_event)
        detection = evaluate_event(parsed)
        alert = format_alert(detection)

        assert alert is not None
        assert "CRITICAL" in alert["subject"]
        assert "SSH" in alert["body"]

    def test_format_root_user_alert(self, sample_root_user_event):
        """Test formatting a root user alert."""
        parsed = parse_event(sample_root_user_event)
        detection = evaluate_event(parsed)
        alert = format_alert(detection)

        assert alert is not None
        assert "CRITICAL" in alert["subject"]
        assert "YES" in alert["body"]

    def test_format_none_detection(self):
        """Test formatting with None detection."""
        alert = format_alert(None)
        assert alert is None