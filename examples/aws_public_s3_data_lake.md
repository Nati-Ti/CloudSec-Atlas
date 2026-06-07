# AWS Public S3 Data Lake

An AWS data lake stores customer exports, payment data, and support logs in several S3 buckets. One bucket policy allows public-read access so external analysts can download weekly files.

The bucket is also used by a Glue job and an Athena reporting workflow. CloudTrail is enabled, but there are no CloudWatch alerts for unusual S3 object reads, and the team has not reviewed whether the bucket policy is still required.
