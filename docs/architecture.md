# System Architecture

## Overview

The AWS Cloud Security Monitoring System uses an event-driven architecture where AWS CloudTrail captures management API events, EventBridge evaluates them against security detection rules, Lambda processes matched events, and SNS delivers email notifications.

## Architecture Flow