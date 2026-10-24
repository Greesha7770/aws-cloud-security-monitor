"""
Pytest configuration and shared fixtures for Lambda tests.
"""

import pytest


@pytest.fixture
def sample_create_user_event():
    """Sample CloudTrail event for IAM CreateUser via EventBridge."""
    return {
        "version": "0",
        "id": "12345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "account": "123456789012",
        "time": "2025-01-15T10:30:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T10:30:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "userName": "new-test-user"
            },
            "responseElements": {
                "user": {
                    "userName": "new-test-user",
                    "userId": "AIDACKCEVSQ6C2EXAMPLE2",
                    "arn": "arn:aws:iam::123456789012:user/new-test-user"
                }
            },
            "eventID": "abcd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_delete_user_event():
    """Sample CloudTrail event for IAM DeleteUser."""
    return {
        "version": "0",
        "id": "22345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "account": "123456789012",
        "time": "2025-01-15T11:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T11:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "DeleteUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "userName": "old-test-user"
            },
            "responseElements": None,
            "eventID": "bbcd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_create_access_key_event():
    """Sample CloudTrail event for IAM CreateAccessKey."""
    return {
        "version": "0",
        "id": "32345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "account": "123456789012",
        "time": "2025-01-15T12:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T12:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "userName": "new-test-user"
            },
            "responseElements": {
                "accessKey": {
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "secretAccessKey": "[REDACTED]",
                    "userName": "new-test-user"
                }
            },
            "eventID": "cccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_attach_user_policy_event():
    """Sample CloudTrail event for AttachUserPolicy."""
    return {
        "version": "0",
        "id": "42345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "account": "123456789012",
        "time": "2025-01-15T13:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T13:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "userName": "new-test-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "responseElements": None,
            "eventID": "dccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_security_group_open_ssh_event():
    """Sample CloudTrail event for AuthorizeSecurityGroupIngress opening SSH to 0.0.0.0/0."""
    return {
        "version": "0",
        "id": "52345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.ec2",
        "account": "123456789012",
        "time": "2025-01-15T14:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T14:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "groupId": "sg-0123456789abcdef0",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {
                                "items": [
                                    {"cidrIp": "0.0.0.0/0"}
                                ]
                            },
                            "ipv6Ranges": {
                                "items": []
                            }
                        }
                    ]
                }
            },
            "responseElements": {
                "requestId": "req-12345",
                "_return": True
            },
            "eventID": "eccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_security_group_open_rdp_ipv6_event():
    """Sample event for security group opening RDP to ::/0 (IPv6)."""
    return {
        "version": "0",
        "id": "62345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.ec2",
        "account": "123456789012",
        "time": "2025-01-15T15:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T15:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "groupId": "sg-0123456789abcdef1",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 3389,
                            "toPort": 3389,
                            "ipRanges": {
                                "items": []
                            },
                            "ipv6Ranges": {
                                "items": [
                                    {"cidrIpv6": "::/0"}
                                ]
                            }
                        }
                    ]
                }
            },
            "responseElements": {
                "requestId": "req-12346",
                "_return": True
            },
            "eventID": "fccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_security_group_safe_event():
    """Sample event for security group rule that is NOT open to the world."""
    return {
        "version": "0",
        "id": "72345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.ec2",
        "account": "123456789012",
        "time": "2025-01-15T16:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T16:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "groupId": "sg-0123456789abcdef2",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 443,
                            "toPort": 443,
                            "ipRanges": {
                                "items": [
                                    {"cidrIp": "10.0.0.0/8"}
                                ]
                            },
                            "ipv6Ranges": {
                                "items": []
                            }
                        }
                    ]
                }
            },
            "responseElements": {
                "requestId": "req-12347",
                "_return": True
            },
            "eventID": "gccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_put_bucket_policy_event():
    """Sample CloudTrail event for S3 PutBucketPolicy."""
    return {
        "version": "0",
        "id": "82345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
        "account": "123456789012",
        "time": "2025-01-15T17:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T17:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "bucketName": "my-sensitive-bucket",
                "bucketPolicy": {
                    "Version": "2012-10-17",
                    "Statement": []
                }
            },
            "responseElements": None,
            "eventID": "hccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_delete_public_access_block_event():
    """Sample CloudTrail event for S3 DeleteBucketPublicAccessBlock."""
    return {
        "version": "0",
        "id": "92345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
        "account": "123456789012",
        "time": "2025-01-15T18:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T18:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeleteBucketPublicAccessBlock",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "bucketName": "my-sensitive-bucket"
            },
            "responseElements": None,
            "eventID": "iccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_console_login_failure_event():
    """Sample CloudTrail event for failed console login."""
    return {
        "version": "0",
        "id": "a2345678-1234-1234-1234-123456789012",
        "detail-type": "AWS Console Sign In via CloudTrail",
        "source": "aws.signin",
        "account": "123456789012",
        "time": "2025-01-15T19:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "accountId": "123456789012",
                "userName": "test-user"
            },
            "eventTime": "2025-01-15T19:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.42",
            "errorMessage": "Failed authentication",
            "requestParameters": None,
            "responseElements": {
                "ConsoleLogin": "Failure"
            },
            "eventID": "jccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_console_login_success_event():
    """Sample CloudTrail event for successful console login."""
    return {
        "version": "0",
        "id": "b2345678-1234-1234-1234-123456789012",
        "detail-type": "AWS Console Sign In via CloudTrail",
        "source": "aws.signin",
        "account": "123456789012",
        "time": "2025-01-15T20:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T20:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": None,
            "responseElements": {
                "ConsoleLogin": "Success"
            },
            "eventID": "kccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_root_user_event():
    """Sample CloudTrail event for root user activity."""
    return {
        "version": "0",
        "id": "c2345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "account": "123456789012",
        "time": "2025-01-15T21:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "Root",
                "principalId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "accountId": "123456789012"
            },
            "eventTime": "2025-01-15T21:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.99",
            "requestParameters": {
                "userName": "suspicious-user"
            },
            "responseElements": {
                "user": {
                    "userName": "suspicious-user"
                }
            },
            "eventID": "lccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def sample_unrelated_event():
    """Sample CloudTrail event that should NOT trigger any alert."""
    return {
        "version": "0",
        "id": "d2345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.ec2",
        "account": "123456789012",
        "time": "2025-01-15T22:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012",
                "userName": "admin-user"
            },
            "eventTime": "2025-01-15T22:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "requestParameters": {
                "instancesSet": {}
            },
            "responseElements": None,
            "eventID": "mccd1234-abcd-1234-abcd-123456789012"
        }
    }


@pytest.fixture
def malformed_event_no_detail():
    """Malformed event with no detail field."""
    return {
        "version": "0",
        "id": "e2345678-1234-1234-1234-123456789012",
        "source": "aws.iam",
    }


@pytest.fixture
def malformed_event_empty():
    """Completely empty event."""
    return {}


@pytest.fixture
def malformed_event_not_dict():
    """Event that is not a dictionary."""
    return "this is not a valid event"