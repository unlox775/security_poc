# AWS Report Classifier

A tool for analyzing and classifying AWS CloudTrail events from CSV exports to identify patterns, security risks, and suspicious activities.

## Features

- **Event Classification**: Automatically categorizes AWS CloudTrail events into security-relevant buckets
- **Data Analysis**: Analyzes event frequency, patterns, and anomalies across multiple CSV files
- **Audit System**: Validates classifier structure and consistency
- **Modular Design**: Service-specific classifiers for different AWS services

## Quick Start

```bash
# Analyze your CloudTrail CSV files
make analyze ENV_DEV_CSV=path/to/dev_events.csv ENV_PROD_CSV=path/to/prod_events.csv

# Audit classifier structure
make audit

# Run unit tests
make test
```

## Commands

- `make analyze` - Analyze CSV files for unclassified events and patterns
- `make audit` - Validate classifier internal consistency
- `make test` - Run unit tests
- `make clean` - Clean up temporary files

## Classification Categories

- **SAFE_READ_ONLY**: Basic information that doesn't expose sensitive data
- **SENSITIVE_READ_ONLY**: Operations that could expose sensitive information
- **SENSITIVE_WRITE**: Operations that modify configurations or data
- **HACKING_READS**: Operations that could be used for reconnaissance
- **STRANGE_READS**: Unusual operations that warrant investigation
- **INFRA_READS**: Infrastructure management operations
- **DASHBOARD_READS**: High-frequency dashboard components
- **UNCLASSIFIED**: Events that need manual review and classification

## Architecture

The tool uses a modular classifier system with service-specific modules:

- **Monitoring**: CloudWatch, Health, Logs, Application Insights
- **Compute**: EC2, Lambda, Auto Scaling
- **Billing**: Cost Explorer, Billing Console, Budgets
- **Identity**: IAM, STS, KMS, Secrets Manager, Organizations
- **IAC**: CloudFormation, CodeBuild, CodePipeline
- **Networking**: Route53, VPC Lattice, API Gateway, Load Balancers
- **Storage**: S3, ElastiCache, DynamoDB, RDS
- **Notifications**: AWS Notifications, Event Schemas
- **Security**: Access Analyzer, Config, GuardDuty, Security Hub

## Usage Examples

```bash
# Analyze specific files
make analyze ENV_DEV_CSV=./data/dev_events.csv ENV_PROD_CSV=./data/prod_events.csv

# Just audit the classifier
make audit

# Run all tests
make test
```
