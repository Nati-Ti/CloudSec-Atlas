# CloudSec Atlas Sample Report

## Architecture Summary

The submitted design appears to describe an AWS cloud environment with public application,
compute, database, identity, network, and storage asset areas. CloudSec Atlas rates the
current posture as High because the database is directly reachable from the internet and
baseline edge, backup, and monitoring controls are incomplete.

## Detected Assets

| Asset | Type | Exposure | Notes |
| --- | --- | --- | --- |
| Public application entry point | Network / Application | Internet-facing | Accepts inbound traffic from users or external clients. |
| Compute workload | Compute | Private or unspecified | Runs application or administrative workloads. |
| Application database | Data Store | Public or broad | Stores application data and may contain sensitive records. |
| Object storage | Storage | Private or unspecified | Stores files, exports, logs, or customer content. |
| Cloud identity and permissions | Identity | Control plane | Grants access to cloud services and administrative operations. |
| Cloud network controls | Network | Boundary control | Defines routing, segmentation, and allowed inbound traffic. |

## Security Findings

### Critical: Database appears directly reachable from the internet

- Evidence: The description references a database with public or 0.0.0.0/0 exposure.
- Impact: Attackers can attempt credential stuffing, exploit unpatched database services, or extract data if credentials are weak or leaked.
- Recommended fix: Move the database to a private subnet, restrict inbound access to trusted application tiers, and require encrypted connections.

### High: Administrative or broad inbound access is exposed

- Evidence: The architecture references broad inbound access through 0.0.0.0/0.
- Impact: Attackers can scan, brute force, or exploit management services before reaching application controls.
- Recommended fix: Remove broad inbound rules and restrict access to approved application paths.

### Medium: Database backup and recovery posture is not described

- Evidence: A database is present, but backups, snapshots, restore testing, or replicas are not mentioned.
- Impact: Destructive changes or operator error could become a prolonged outage or permanent data loss.
- Recommended fix: Enable automated backups, test restores, and protect snapshots from accidental or malicious deletion.

## Attack Paths

### Internet to exposed database

- Attacker scans cloud IP ranges or DNS records for reachable database ports.
- Attacker attempts password spraying, credential reuse, or known database exploits.
- Attacker reads or modifies application data directly, bypassing the application tier.

## Blast Radius

- Data tier risk: application records, customer data, backups, and database availability may be affected.
- Network risk: exposed management paths or weak segmentation can allow lateral movement beyond the first workload.
- Detection risk: incident scope may be hard to prove if telemetry is incomplete.

## Prioritized Fix Roadmap

| Priority | Action | Expected Outcome |
| --- | --- | --- |
| P0 | Remove direct public database access and allow only the application tier over required ports. | Eliminates the highest-risk direct data-store attack path. |
| P1 | Close broad inbound access and confirm only expected public application ports are reachable. | Reduces internet-facing footholds. |
| P2 | Enable logging, alerting, WAF protections, backups, restore tests, and encryption validation. | Improves resilience, detection, and containment. |

## Verification Checklist

- [ ] Confirm the database is private and reachable only from approved application subnets or services.
- [ ] Verify security groups do not allow database or management access from 0.0.0.0/0.
- [ ] Confirm public endpoints are protected by WAF, rate limiting, TLS, and request logging.
- [ ] Perform a restore test from the latest database backup or snapshot.
- [ ] Re-run CloudSec Atlas after remediation.

## Safer Target Architecture

- Public users reach only the application edge, protected by WAF, TLS, and rate limits.
- Application workloads run in private subnets and access the database through restricted security groups.
- The database is private, encrypted, monitored, backed up, and recoverable.
- IAM roles are scoped to required actions and resources.
- Security telemetry is centralized with alerts for risky identity, network, storage, and data events.
