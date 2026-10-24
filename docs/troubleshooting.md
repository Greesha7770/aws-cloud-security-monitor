# Troubleshooting Guide

## Common Issues & Solutions

### 1. Email Alerts Not Arriving

- **Check Spam/Junk Folder:** SNS confirmation and alerts can land in spam.
- **Verify Subscription Status:**
  ```powershell
  aws sns list-subscriptions-by-topic --topic-arn YOUR_SNS_TOPIC_ARN