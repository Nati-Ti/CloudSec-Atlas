# CloudSec Atlas Analysis Report

## Architecture Summary

The submitted design appears to describe an AWS cloud environment with 6 detected asset area(s): Compute, Data Store, Identity, Network, Network / Application, Storage. CloudSec Atlas rates the current posture as Critical. The key risk chain is direct internet reachability to RDS, where the application stores customer profile data and billing metadata. The score is driven by direct internet reachability to the data tier.

## Detected Assets

| Asset | Type | Exposure | Notes |
| --- | --- | --- | --- |
| Public application entry point | Network / Application | Internet-facing | Accepts inbound traffic from users or external clients. |
| Compute workload | Compute | Private or unspecified | Runs application or administrative workloads. |
| RDS PostgreSQL database | Data Store | Public or broad | Stores customer profile data and billing metadata. |
| Amazon S3 storage | Storage | Private or unspecified | Stores files, exports, logs, or customer content. |
| Cloud identity and permissions | Identity | Control plane | Grants access to cloud services and administrative operations. |
| Cloud network controls | Network | Boundary control | Defines routing, segmentation, and allowed inbound traffic. |

## Security Findings

Overall risk: **Critical** (94/100)

### Score Drivers

- Public RDS exposure: +40
- Sensitive customer data in exposed data tier: +25
- Broad PostgreSQL ingress from 0.0.0.0/0: +20
- Missing WAF and recovery evidence: +9

### Critical: RDS appears directly reachable from the internet

- ID: `CSA-001`
- Confidence: High
- Affected assets: RDS PostgreSQL database, Cloud network controls
- Evidence: The description references RDS with public or 0.0.0.0/0 exposure.

Why this matters: A public RDS endpoint bypasses the normal application security layer. Even if the web app is protected, attackers can directly target PostgreSQL using credential reuse, password spraying, or database-service exploitation.

- Impact: An attacker can attempt credential stuffing, exploit unpatched database services, or extract data if credentials are weak or leaked.
- Recommended fix: Move RDS behind private subnets, restrict inbound access with Security Groups and NACLs, and require encrypted connections.

### High: Sensitive data is stored in RDS PostgreSQL database

- ID: `CSA-018`
- Confidence: High
- Affected assets: RDS PostgreSQL database
- Evidence: The architecture says the application stores customer profile data and billing metadata in RDS PostgreSQL database.

Why this matters: The exposed data tier contains customer profile data and billing metadata. If RDS is reachable from the internet, compromise affects customer data directly rather than only the web application.

- Impact: If the exposed data tier is compromised, an attacker can read or alter customer profile data and billing metadata directly.
- Recommended fix: Keep RDS private, encrypt and back up sensitive records, restrict application access, and monitor data-tier activity.

### High: Broad inbound database access is exposed

- ID: `CSA-019`
- Confidence: High
- Affected assets: RDS PostgreSQL database, Cloud network controls
- Evidence: The RDS security group allows PostgreSQL traffic from 0.0.0.0/0.

Why this matters: The Security Group rule makes PostgreSQL reachable from any internet source. That turns the database listener itself into an attack surface instead of limiting database access to the EC2 application tier.

- Impact: Attackers can directly target the PostgreSQL listener from the internet, increasing exposure to password spraying, credential reuse, and database-service exploitation.
- Recommended fix: Restrict PostgreSQL ingress to approved application Security Groups or private subnets only.

### Medium: RDS backup and recovery posture is not described

- ID: `CSA-009`
- Confidence: Medium
- Affected assets: RDS PostgreSQL database
- Evidence: RDS is present, but backups, snapshots, restore testing, or replicas are not mentioned.

Why this matters: The architecture describes sensitive records in RDS but does not prove restore readiness. Without tested recovery, a destructive database event can become both a data-loss incident and an extended outage.

- Impact: Ransomware, destructive changes, or operator error could become a prolonged outage or permanent data loss.
- Recommended fix: Enable automated backups, test restores, and protect snapshots from accidental or malicious deletion.

### Medium: Public application edge lacks described protective controls

- ID: `CSA-010`
- Confidence: Medium
- Affected assets: Public application entry point
- Evidence: A public ALB or API Gateway entry point is described, but AWS WAF, rate limiting, DDoS, or bot controls are not mentioned.

Why this matters: The architecture has an internet-facing application edge, but no AWS WAF or rate-limit evidence. That leaves the public entry point easier to scan, abuse, and use as reconnaissance for the exposed data tier.

- Impact: The application is more exposed to commodity scanning, volumetric abuse, and simple exploit attempts.
- Recommended fix: Add AWS WAF protections, request rate limits, managed DDoS protection, and application-layer alerting.

## Attack Paths

### Public application edge to exposed data tier

- Difficulty: Low to Medium
- Likely impact: Direct exposure of customer profile data and billing metadata through a reachable data-tier listener.
- Steps:
  - Attacker finds the internet-facing application and associated infrastructure.
  - Attacker identifies reachable PostgreSQL/RDS exposure or obtains database credentials through leakage or reuse.
  - Attacker connects directly to the public RDS endpoint.
  - Attacker reads or modifies customer profile data and billing metadata.
- Broken by: Restrict PostgreSQL ingress to approved application Security Groups or private subnets only.

## Blast Radius

- Data tier risk: customer profile data and billing metadata, backups, and RDS availability may be affected.
- Database ingress risk: PostgreSQL traffic from the internet can reach RDS PostgreSQL database, increasing the chance of direct credential attacks or database-service exploitation.
- Assets considered in scope: Public application entry point, Compute workload, RDS PostgreSQL database, Amazon S3 storage, Cloud identity and permissions, Cloud network controls.

## Prioritized Fix Roadmap

| Priority | Action | Expected Outcome |
| --- | --- | --- |
| P0 | Disable public accessibility on RDS and remove 0.0.0.0/0 from PostgreSQL Security Group ingress. | Immediately removes direct internet reachability to the PostgreSQL listener. |
| P1 | Move RDS into private subnets and allow PostgreSQL only from the EC2 application Security Group. | Restores the intended application-to-database trust boundary. |
| P2 | Enable CloudTrail, CloudWatch alerts, ALB or API Gateway request logging, AWS WAF protections, rate limiting, GuardDuty, and VPC Flow Logs where available. | Improves detection of public-edge abuse, control-plane changes, and suspicious network activity. |
| P3 | Test RDS backup/restore, document the target architecture, run a tabletop review, and re-run CloudSec Atlas. | Confirms the risk chain is broken and turns remediation into repeatable verification. |

## Verification Checklist

- [ ] Confirm all public endpoints are intentionally exposed and protected by edge controls.
- [ ] Validate that CloudTrail logs are enabled and routed to CloudWatch.
- [ ] Review IAM roles and policies for least privilege, resource scoping, and removal of wildcard permissions.
- [ ] Verify RDS is private and reachable only from approved application subnets or services.
- [ ] Confirm customer profile data and billing metadata are protected in RDS with least-privilege access and data-tier monitoring.
- [ ] Restrict PostgreSQL ingress to approved application Security Groups or private subnets only.
- [ ] Perform a restore test from the latest RDS backup or snapshot.
- [ ] Re-run CloudSec Atlas after remediation and confirm critical and high findings are cleared.

## Safer Target Architecture

- Use a public edge layer only where required, protected by AWS WAF, rate limiting, TLS, and request logging.
- Place application workloads in private subnets or managed private runtimes with explicit outbound paths.
- Keep data stores private, encrypted, backed up, and reachable only from approved workloads.
- Use IAM Identity Center, federated identity, IAM roles, or temporary STS credentials with least-privilege permissions and MFA for administrators.
- Centralize CloudTrail logs, security telemetry, and alerts in CloudWatch for identity, network, storage, and data access events.
- Serve private Amazon S3 through pre-signed URLs, IAM roles, temporary STS credentials, CloudFront origin access controls, or authenticated application flows.
- Add tested RDS recovery with point-in-time restore, protected snapshots, and deletion safeguards.

## Source Architecture Description

```text
# Startup Public Database Scenario

A small SaaS startup runs an AWS web application behind an internet-facing load balancer.
Two EC2 app servers sit in the same VPC as an RDS PostgreSQL database.

The RDS database is publicly accessible for convenience during development, and the security
group allows PostgreSQL traffic from 0.0.0.0/0. The EC2 instances use an IAM role that can
read from S3 and write application logs. There is no WAF yet, and the team has not documented
database backups or restore testing.

The application stores customer profile data and billing metadata in PostgreSQL.
```
