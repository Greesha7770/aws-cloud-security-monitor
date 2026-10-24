"""
Tests for the Lambda handler module.
"""

import pytest
import sys
import os
import json
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestLambdaHandler:
    """Tests for the lambda_handler function."""

    @patch.dict(os.environ, {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic", "LOG_LEVEL": "INFO"})
    @patch("handler.sns_client")
    def test_handler_sends_alert_for_create_user(self, mock_sns, sample_create_user_event):
        """Test that handler sends SNS notification for CreateUser event."""
        from handler import lambda_handler

        mock_sns.publish.return_value = {"MessageId": "test-message-id-123"}

        result = lambda_handler(sample_create_user_event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "sent successfully" in body["message"].lower()
        mock_sns.publish.assert_called_once()

    @patch.dict(os.environ, {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic", "LOG_LEVEL": "INFO"})
    @patch("handler.sns_client")
    def test_handler_skips_unrelated_event(self, mock_sns, sample_unrelated_event):
        """Test that handler skips events that don't match detection rules."""
        from handler import lambda_handler

        result = lambda_handler(sample_unrelated_event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "skipped" in body["message"].lower()
        mock_sns.publish.assert_not_called()