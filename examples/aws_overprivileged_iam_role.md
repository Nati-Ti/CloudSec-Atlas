# AWS Overprivileged IAM Role

A data processing workflow in AWS uses Lambda functions, S3 buckets, and DynamoDB tables. The Lambda execution role has AdministratorAccess because the team wanted to avoid blocked deployments during the prototype phase.

A developer keeps an access key in code for a utility script that uploads test files to S3. API Gateway invokes the Lambda workflow, MFA is not required for the shared admin user, and monitoring is limited to basic application logs.

The system processes partner data and generates reports for internal users.
