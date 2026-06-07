# AWS Startup Public Database

A small SaaS startup runs an AWS web application behind an internet-facing load balancer. Two EC2 app servers sit in the same VPC as an RDS PostgreSQL database.

The RDS database is publicly accessible for convenience during development, and the security group allows PostgreSQL traffic from 0.0.0.0/0. The EC2 instances use an IAM role that can read from S3 and write application logs. There is no AWS WAF yet, and the team has not documented database backups or restore testing.

The application stores customer profile data and billing metadata in PostgreSQL.
