from __future__ import annotations

import re
from typing import Iterable, List

from agent.schemas import AnalysisReport, Asset, AttackPath, Finding, RoadmapItem


SEVERITY_WEIGHTS = {
    "Critical": 35,
    "High": 22,
    "Medium": 10,
    "Low": 4,
}


def analyze_architecture(description: str) -> AnalysisReport:
    text = _normalize(description)
    assets = _detect_assets(text)
    findings = _detect_findings(text, assets)
    attack_paths = _build_attack_paths(text, findings, assets)
    risk_score = _score_findings(findings)
    risk_label = _risk_label(risk_score)

    return AnalysisReport(
        architecture_summary=_summarize_architecture(text, assets, findings, risk_label),
        assets=assets,
        findings=findings,
        attack_paths=attack_paths,
        blast_radius=_estimate_blast_radius(text, assets, findings),
        fix_roadmap=_build_roadmap(findings),
        verification_checklist=_build_verification_checklist(findings),
        safer_target_architecture=_build_target_architecture(text, assets, findings),
        risk_score=risk_score,
        risk_label=risk_label,
    )


def render_report_markdown(report: AnalysisReport, source_description: str) -> str:
    lines = [
        "# CloudSec Atlas Analysis Report",
        "",
        "## Architecture Summary",
        report.architecture_summary,
        "",
        "## Detected Assets",
        "| Asset | Type | Exposure | Notes |",
        "| --- | --- | --- | --- |",
    ]

    for asset in report.assets:
        lines.append(
            f"| {_escape_md(asset.name)} | {_escape_md(asset.type)} | "
            f"{_escape_md(asset.exposure)} | {_escape_md(asset.notes)} |"
        )

    lines.extend(
        [
            "",
            "## Security Findings",
            f"Overall risk: **{report.risk_label}** ({report.risk_score}/100)",
            "",
        ]
    )

    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.severity}: {finding.title}",
                f"- ID: `{finding.id}`",
                f"- Confidence: {finding.confidence}",
                f"- Affected assets: {', '.join(finding.affected_assets)}",
                f"- Evidence: {finding.evidence}",
                f"- Impact: {finding.impact}",
                f"- Recommended fix: {finding.recommendation}",
                "",
            ]
        )

    lines.extend(["## Attack Paths", ""])
    for path in report.attack_paths:
        lines.extend(
            [
                f"### {path.name}",
                f"- Difficulty: {path.difficulty}",
                f"- Likely impact: {path.impact}",
                "- Steps:",
            ]
        )
        lines.extend([f"  - {step}" for step in path.steps])
        lines.extend([f"- Broken by: {path.blocked_by}", ""])

    lines.extend(["## Blast Radius", ""])
    lines.extend([f"- {item}" for item in report.blast_radius])

    lines.extend(
        [
            "",
            "## Prioritized Fix Roadmap",
            "| Priority | Action | Expected Outcome |",
            "| --- | --- | --- |",
        ]
    )
    for item in report.fix_roadmap:
        lines.append(
            f"| {_escape_md(item.priority)} | {_escape_md(item.action)} | "
            f"{_escape_md(item.expected_outcome)} |"
        )

    lines.extend(["", "## Verification Checklist", ""])
    lines.extend([f"- [ ] {item}" for item in report.verification_checklist])

    lines.extend(["", "## Safer Target Architecture", ""])
    lines.extend([f"- {item}" for item in report.safer_target_architecture])

    lines.extend(["", "## Source Architecture Description", "", "```text", source_description.strip(), "```"])
    return "\n".join(lines)


def _detect_assets(text: str) -> List[Asset]:
    assets: List[Asset] = []

    if _has_any(text, ["internet-facing", "public api", "api gateway", "load balancer", "alb", "app service", "frontend", "web app"]):
        assets.append(
            Asset(
                name="Public application entry point",
                type="Network / Application",
                exposure="Internet-facing",
                notes="Accepts inbound traffic from users or external clients.",
            )
        )

    if _has_any(text, ["vm", "virtual machine", "ec2", "compute instance", "web server", "app server"]):
        assets.append(
            Asset(
                name="Compute workload",
                type="Compute",
                exposure=_exposure(text, ["public vm", "public ec2", "ssh open", "rdp open", "0.0.0.0/0"]),
                notes="Runs application or administrative workloads.",
            )
        )

    if _has_any(text, ["lambda", "azure function", "cloud function", "serverless"]):
        assets.append(
            Asset(
                name="Serverless function",
                type="Compute",
                exposure="Event-driven",
                notes="Executes application logic without managed servers.",
            )
        )

    if _has_any(text, ["rds", "database", "postgres", "postgresql", "mysql", "sql server", "aurora", "cosmos db", "dynamodb"]):
        assets.append(
            Asset(
                name="Application database",
                type="Data Store",
                exposure=_exposure(text, ["public database", "publicly accessible", "internet accessible", "0.0.0.0/0", "open to the internet"]),
                notes="Stores application data and may contain sensitive records.",
            )
        )

    if _has_any(text, ["s3", "bucket", "blob", "storage account", "object storage", "gcs"]):
        assets.append(
            Asset(
                name="Object storage",
                type="Storage",
                exposure=_exposure(text, ["public bucket", "public-read", "anonymous", "world-readable", "public blob", "public access"]),
                notes="Stores files, exports, logs, or customer content.",
            )
        )

    if _has_any(text, ["iam", "role", "policy", "service principal", "managed identity", "access key", "administratoraccess", "contributor", "owner"]):
        assets.append(
            Asset(
                name="Cloud identity and permissions",
                type="Identity",
                exposure="Control plane",
                notes="Grants access to cloud services and administrative operations.",
            )
        )

    if _has_any(text, ["vpc", "subnet", "security group", "nsg", "firewall", "network", "vpn"]):
        assets.append(
            Asset(
                name="Cloud network controls",
                type="Network",
                exposure="Boundary control",
                notes="Defines routing, segmentation, and allowed inbound traffic.",
            )
        )

    if _has_any(text, ["secret", "secrets manager", "key vault", "kms", "key management", ".env", "password", "token"]):
        assets.append(
            Asset(
                name="Secrets and encryption keys",
                type="Secrets",
                exposure="Privileged",
                notes="Protects credentials, tokens, and encryption material.",
            )
        )

    if _has_any(text, ["kubernetes", "aks", "eks", "gke", "cluster", "container"]):
        assets.append(
            Asset(
                name="Container platform",
                type="Container / Orchestration",
                exposure="Cluster managed",
                notes="Hosts containerized services and workload identities.",
            )
        )

    if not assets:
        assets.append(
            Asset(
                name="Unspecified cloud workload",
                type="Unknown",
                exposure="Unknown",
                notes="Provide more service, network, identity, and data details for deeper analysis.",
            )
        )

    return assets


def _detect_findings(text: str, assets: List[Asset]) -> List[Finding]:
    findings: List[Finding] = []

    if _has_database(text) and _has_any(text, ["public database", "publicly accessible", "internet accessible", "open to the internet", "0.0.0.0/0"]):
        findings.append(
            Finding(
                id="CSA-001",
                title="Database appears directly reachable from the internet",
                severity="Critical",
                confidence="High",
                evidence="The description references a database with public or 0.0.0.0/0 exposure.",
                impact="An attacker can attempt credential stuffing, exploit unpatched database services, or extract data if credentials are weak or leaked.",
                recommendation="Move the database to a private subnet, restrict inbound access to trusted application tiers, and require encrypted connections.",
                affected_assets=["Application database", "Cloud network controls"],
            )
        )

    if _has_storage(text) and _has_any(text, ["public bucket", "public-read", "anonymous", "world-readable", "public blob", "public access"]):
        findings.append(
            Finding(
                id="CSA-002",
                title="Object storage may allow public access",
                severity="High",
                confidence="High",
                evidence="The description includes object storage with public, anonymous, or world-readable access.",
                impact="Sensitive files, backups, logs, or exported data may be exposed without authentication.",
                recommendation="Block public access, apply least-privilege bucket policies, and use signed URLs or private endpoints for controlled access.",
                affected_assets=["Object storage"],
            )
        )

    if _has_any(text, ["administratoraccess", "admin access", "full admin", "owner role", "contributor role", "iam *", "resource *", "*:*", "wildcard permissions", "all resources"]):
        findings.append(
            Finding(
                id="CSA-003",
                title="Identity permissions look overprivileged",
                severity="High",
                confidence="High",
                evidence="The description references administrator, owner, contributor, wildcard, or all-resource permissions.",
                impact="Compromise of one credential can become broad cloud control-plane compromise.",
                recommendation="Replace broad roles with least-privilege policies scoped to required actions, resources, and environments.",
                affected_assets=["Cloud identity and permissions"],
            )
        )

    if _has_any(text, ["hardcoded secret", "hardcoded key", ".env in repo", "plaintext secret", "access key in code", "password in code", "token in code"]):
        findings.append(
            Finding(
                id="CSA-004",
                title="Secrets may be stored in code or plaintext",
                severity="High",
                confidence="Medium",
                evidence="The description suggests secrets are hardcoded, stored in a repository, or kept in plaintext.",
                impact="A code leak, developer laptop compromise, or log exposure could reveal credentials that unlock cloud resources.",
                recommendation="Move secrets to a managed secret store, rotate exposed credentials, and add repository secret scanning.",
                affected_assets=["Secrets and encryption keys", "Cloud identity and permissions"],
            )
        )

    if _has_any(text, ["ssh open", "rdp open", "22 open", "3389 open", "management port", "any source", "0.0.0.0/0"]):
        findings.append(
            Finding(
                id="CSA-005",
                title="Administrative or broad inbound access is exposed",
                severity="High",
                confidence="Medium",
                evidence="The architecture references broad inbound access, management ports, any-source rules, or 0.0.0.0/0.",
                impact="Attackers can scan, brute force, or exploit management services before reaching application controls.",
                recommendation="Remove public management ports, use a bastion or just-in-time access, and restrict inbound rules to trusted sources.",
                affected_assets=["Compute workload", "Cloud network controls"],
            )
        )

    if _has_any(text, ["no mfa", "without mfa", "mfa disabled", "single factor"]):
        findings.append(
            Finding(
                id="CSA-006",
                title="Privileged access may not require MFA",
                severity="Medium",
                confidence="High",
                evidence="The description says MFA is disabled or not required.",
                impact="Password or token theft is more likely to result in successful administrative access.",
                recommendation="Require phishing-resistant MFA for administrators and conditional access for risky sign-ins.",
                affected_assets=["Cloud identity and permissions"],
            )
        )

    if _has_any(text, ["unencrypted", "no encryption", "encryption disabled", "not encrypted"]):
        findings.append(
            Finding(
                id="CSA-007",
                title="Data encryption is missing or unclear",
                severity="Medium",
                confidence="Medium",
                evidence="The description references unencrypted data or disabled encryption.",
                impact="Data exposure becomes more damaging if storage, backups, snapshots, or traffic are intercepted or copied.",
                recommendation="Enable encryption at rest and in transit with managed keys, and document key ownership and rotation.",
                affected_assets=_affected_data_assets(assets),
            )
        )

    if _logging_missing(text):
        findings.append(
            Finding(
                id="CSA-008",
                title="Detection and logging controls are not described",
                severity="Medium",
                confidence="Medium",
                evidence="The input does not mention audit logs, monitoring, alerting, or security telemetry.",
                impact="Compromise may go undetected, delaying containment and forensic investigation.",
                recommendation="Enable cloud audit logs, centralize security telemetry, and alert on risky identity, network, and data events.",
                affected_assets=["Cloud identity and permissions", "Cloud network controls"],
            )
        )

    if _has_database(text) and _backup_missing(text):
        findings.append(
            Finding(
                id="CSA-009",
                title="Database backup and recovery posture is not described",
                severity="Medium",
                confidence="Medium",
                evidence="A database is present, but backups, snapshots, restore testing, or replicas are not mentioned.",
                impact="Ransomware, destructive changes, or operator error could become a prolonged outage or permanent data loss.",
                recommendation="Enable automated backups, test restores, and protect snapshots from accidental or malicious deletion.",
                affected_assets=["Application database"],
            )
        )

    if _has_any(text, ["public api", "api gateway", "internet-facing", "web app", "load balancer"]) and _edge_protection_missing(text):
        findings.append(
            Finding(
                id="CSA-010",
                title="Public application edge lacks described protective controls",
                severity="Medium",
                confidence="Medium",
                evidence="A public application entry point is described, but WAF, rate limiting, DDoS, or bot controls are not mentioned.",
                impact="The application is more exposed to commodity scanning, volumetric abuse, and simple exploit attempts.",
                recommendation="Add WAF protections, request rate limits, managed DDoS protection, and application-layer alerting.",
                affected_assets=["Public application entry point"],
            )
        )

    if _has_any(text, ["flat network", "same subnet", "no segmentation", "single subnet"]):
        findings.append(
            Finding(
                id="CSA-011",
                title="Network segmentation appears weak",
                severity="Medium",
                confidence="High",
                evidence="The description references a flat network, same subnet, single subnet, or lack of segmentation.",
                impact="A compromised workload may move laterally to data stores, identity services, or management interfaces.",
                recommendation="Separate public, application, data, and management tiers with deny-by-default network rules.",
                affected_assets=["Cloud network controls", "Compute workload", "Application database"],
            )
        )

    if _has_any(text, ["no authentication", "unauthenticated", "anonymous api", "no auth"]):
        findings.append(
            Finding(
                id="CSA-012",
                title="Application endpoint may allow unauthenticated access",
                severity="High",
                confidence="High",
                evidence="The description references no authentication, anonymous API use, or unauthenticated access.",
                impact="Attackers can access application functions directly and may enumerate or alter data.",
                recommendation="Require strong authentication and authorization checks for every sensitive endpoint.",
                affected_assets=["Public application entry point"],
            )
        )

    if not findings:
        findings.append(
            Finding(
                id="CSA-000",
                title="No high-confidence rule match found",
                severity="Low",
                confidence="Medium",
                evidence="The deterministic rules did not find explicit risky patterns in the provided description.",
                impact="The architecture may still have risks that require configuration review, threat modeling, or cloud inventory scanning.",
                recommendation="Add more detail about identity roles, network paths, data sensitivity, logging, backups, and encryption.",
                affected_assets=[asset.name for asset in assets],
            )
        )

    return _dedupe_findings(findings)


def _build_attack_paths(text: str, findings: List[Finding], assets: List[Asset]) -> List[AttackPath]:
    finding_ids = {finding.id for finding in findings}
    paths: List[AttackPath] = []

    if "CSA-001" in finding_ids:
        paths.append(
            AttackPath(
                name="Internet to exposed database",
                difficulty="Low to Medium",
                steps=[
                    "Attacker scans cloud IP ranges or DNS records for reachable database ports.",
                    "Attacker attempts password spraying, credential reuse, or known database exploits.",
                    "Attacker reads or modifies application data directly, bypassing the application tier.",
                ],
                impact="Direct compromise of sensitive records and potential destructive data changes.",
                blocked_by="Private database networking, restrictive security groups, strong authentication, and database activity monitoring.",
            )
        )

    if "CSA-002" in finding_ids:
        paths.append(
            AttackPath(
                name="Public storage to data exposure",
                difficulty="Low",
                steps=[
                    "Attacker discovers a public bucket or storage endpoint through search, logs, source code, or naming patterns.",
                    "Attacker lists or downloads accessible objects.",
                    "Attacker uses exposed files, backups, or logs to identify customers, credentials, or internal services.",
                ],
                impact="Sensitive data disclosure and possible follow-on credential compromise.",
                blocked_by="Public access blocks, private endpoints, least-privilege storage policies, and object-level audit alerts.",
            )
        )

    if "CSA-003" in finding_ids or "CSA-004" in finding_ids:
        paths.append(
            AttackPath(
                name="Credential compromise to cloud control-plane escalation",
                difficulty="Medium",
                steps=[
                    "Attacker obtains an access key, token, service principal secret, or developer credential.",
                    "Attacker enumerates granted permissions and discovers broad administrative scope.",
                    "Attacker creates persistence, accesses data services, or changes security controls.",
                ],
                impact="Broad account, subscription, or project compromise depending on permission scope.",
                blocked_by="Least-privilege IAM, short-lived credentials, MFA, secret rotation, and alerting on privilege changes.",
            )
        )

    if "CSA-005" in finding_ids:
        paths.append(
            AttackPath(
                name="Public management access to workload compromise",
                difficulty="Medium",
                steps=[
                    "Attacker scans for exposed SSH, RDP, or management services.",
                    "Attacker attempts brute force, leaked key reuse, or service exploitation.",
                    "Attacker lands on a compute host and pivots toward credentials, data stores, or internal APIs.",
                ],
                impact="Initial foothold in the cloud network and potential lateral movement.",
                blocked_by="No public management ports, bastion access, just-in-time admin, and endpoint hardening.",
            )
        )

    if "CSA-012" in finding_ids:
        paths.append(
            AttackPath(
                name="Unauthenticated API to business data access",
                difficulty="Low",
                steps=[
                    "Attacker finds the public endpoint through DNS, application traffic, or search.",
                    "Attacker calls sensitive API routes without valid user context.",
                    "Attacker enumerates records, changes state, or chains the access into downstream services.",
                ],
                impact="Unauthorized data access and business workflow manipulation.",
                blocked_by="Authentication, authorization checks, rate limiting, and API audit logging.",
            )
        )

    if not paths:
        paths.append(
            AttackPath(
                name="Reconnaissance to configuration abuse",
                difficulty="Unknown",
                steps=[
                    "Attacker profiles public endpoints, cloud metadata, exposed files, and identity hints.",
                    "Attacker looks for weak identity, network, storage, or logging controls.",
                    "Attacker attempts the most exposed control first, then pivots based on discovered permissions.",
                ],
                impact="Depends on actual configuration details not present in the architecture description.",
                blocked_by="Detailed threat modeling, asset inventory, least privilege, private networking, and monitored control-plane activity.",
            )
        )

    return paths


def _estimate_blast_radius(text: str, assets: List[Asset], findings: List[Finding]) -> List[str]:
    finding_ids = {finding.id for finding in findings}
    radius: List[str] = []

    if "CSA-001" in finding_ids or "CSA-009" in finding_ids:
        radius.append("Data tier risk: application records, customer data, backups, and database availability may be affected.")

    if "CSA-002" in finding_ids:
        radius.append("Storage risk: any public objects, exports, logs, or backups in the affected storage location may be exposed.")

    if "CSA-003" in finding_ids or "CSA-004" in finding_ids:
        radius.append("Identity-plane risk: overprivileged credentials could affect multiple services, environments, or cloud resources.")

    if "CSA-005" in finding_ids or "CSA-011" in finding_ids:
        radius.append("Network risk: exposed management paths or weak segmentation can allow lateral movement beyond the first workload.")

    if "CSA-008" in finding_ids:
        radius.append("Detection risk: incident scope may be hard to prove because audit, monitoring, or alert coverage is not described.")

    if not radius:
        radius.append("Blast radius cannot be confidently estimated without more detail about data sensitivity, identity scope, and network boundaries.")

    radius.append(f"Assets considered in scope: {', '.join(asset.name for asset in assets)}.")
    return radius


def _build_roadmap(findings: List[Finding]) -> List[RoadmapItem]:
    finding_ids = {finding.id for finding in findings}
    roadmap: List[RoadmapItem] = []

    if "CSA-001" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P0",
                action="Remove direct public database access and allow only the application tier over required ports.",
                expected_outcome="Eliminates the highest-risk direct data-store attack path.",
            )
        )

    if "CSA-002" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P0",
                action="Block public object storage access and review all bucket or container policies.",
                expected_outcome="Prevents anonymous data retrieval and reduces accidental disclosure.",
            )
        )

    if "CSA-003" in finding_ids or "CSA-004" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action="Rotate exposed credentials and replace broad IAM grants with least-privilege roles.",
                expected_outcome="Limits the impact of credential theft and reduces control-plane blast radius.",
            )
        )

    if "CSA-005" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action="Close public management ports and move administration behind bastion or just-in-time access.",
                expected_outcome="Reduces internet-facing footholds and brute-force opportunities.",
            )
        )

    if "CSA-012" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action="Require authentication and authorization for sensitive API operations.",
                expected_outcome="Stops anonymous access to application functions and data.",
            )
        )

    if any(finding_id in finding_ids for finding_id in ["CSA-006", "CSA-007", "CSA-008", "CSA-009", "CSA-010", "CSA-011"]):
        roadmap.append(
            RoadmapItem(
                priority="P2",
                action="Harden baseline controls: MFA, encryption, backups, segmentation, WAF, logging, and alerting.",
                expected_outcome="Improves resilience, detection, and containment across the environment.",
            )
        )

    roadmap.append(
        RoadmapItem(
            priority="P3",
            action="Document the target architecture and run a tabletop verification against the attack paths.",
            expected_outcome="Turns remediation into repeatable engineering and security validation.",
        )
    )

    return roadmap


def _build_verification_checklist(findings: List[Finding]) -> List[str]:
    checklist = [
        "Confirm all public endpoints are intentionally exposed and protected by edge controls.",
        "Validate that cloud audit logs are enabled and routed to a monitored location.",
        "Review IAM roles for least privilege, resource scoping, and removal of wildcard permissions.",
    ]

    finding_ids = {finding.id for finding in findings}
    if "CSA-001" in finding_ids:
        checklist.append("Verify the database is private and reachable only from approved application subnets or services.")
    if "CSA-002" in finding_ids:
        checklist.append("Run storage public-access checks and confirm anonymous reads are blocked.")
    if "CSA-003" in finding_ids or "CSA-004" in finding_ids:
        checklist.append("Rotate suspected credentials and confirm no long-lived secrets remain in code or plaintext stores.")
    if "CSA-005" in finding_ids:
        checklist.append("Scan security groups or firewall rules for public SSH, RDP, and management ports.")
    if "CSA-007" in finding_ids:
        checklist.append("Confirm encryption at rest and in transit for data stores, storage, backups, and service traffic.")
    if "CSA-009" in finding_ids:
        checklist.append("Perform a restore test from the latest database backup or snapshot.")

    checklist.append("Re-run CloudSec Atlas after remediation and confirm critical and high findings are cleared.")
    return checklist


def _build_target_architecture(text: str, assets: List[Asset], findings: List[Finding]) -> List[str]:
    target = [
        "Use a public edge layer only where required, protected by WAF, rate limiting, TLS, and request logging.",
        "Place application workloads in private subnets or managed private runtimes with explicit outbound paths.",
        "Keep data stores private, encrypted, backed up, and reachable only from approved workloads.",
        "Use managed identities or short-lived credentials with least-privilege permissions and MFA for administrators.",
        "Centralize audit logs, security telemetry, and alerts for identity, network, storage, and data access events.",
    ]

    if _has_storage(text):
        target.append("Serve private object storage through signed URLs, CDN origin access controls, or authenticated application flows.")
    if _has_database(text):
        target.append("Add tested database recovery with point-in-time restore, protected snapshots, and deletion safeguards.")
    if _has_any(text, ["kubernetes", "aks", "eks", "gke", "container"]):
        target.append("Constrain workload identity, network policies, admission controls, and image provenance for container workloads.")

    return target


def _summarize_architecture(text: str, assets: List[Asset], findings: List[Finding], risk_label: str) -> str:
    provider = _detect_provider(text)
    asset_types = ", ".join(sorted({asset.type for asset in assets}))
    top_findings = [finding.title for finding in findings if finding.severity in {"Critical", "High"}]

    if top_findings:
        risk_sentence = f"The most important risks are: {', '.join(top_findings[:3])}."
    else:
        risk_sentence = "No explicit critical or high-risk rule match was found, but the design still needs configuration validation."

    return (
        f"The submitted design appears to describe a {provider} cloud environment with "
        f"{len(assets)} detected asset area(s): {asset_types}. CloudSec Atlas rates the current "
        f"posture as {risk_label}. {risk_sentence}"
    )


def _detect_provider(text: str) -> str:
    providers = []
    if _has_any(text, ["aws", "s3", "rds", "ec2", "lambda", "iam", "cloudtrail", "guardduty", "aurora", "dynamodb"]):
        providers.append("AWS")
    if _has_any(text, ["azure", "blob", "storage account", "nsg", "app service", "key vault", "defender", "sentinel", "managed identity"]):
        providers.append("Azure")
    if _has_any(text, ["gcp", "google cloud", "gcs", "cloud sql", "gke", "security command center"]):
        providers.append("Google Cloud")
    if not providers:
        return "provider-neutral"
    return " / ".join(providers)


def _score_findings(findings: List[Finding]) -> int:
    score = sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)
    return min(100, max(0, score))


def _risk_label(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _dedupe_findings(findings: Iterable[Finding]) -> List[Finding]:
    seen = set()
    unique = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        unique.append(finding)
    return unique


def _affected_data_assets(assets: List[Asset]) -> List[str]:
    affected = [asset.name for asset in assets if asset.type in {"Data Store", "Storage"}]
    return affected or ["Data stores and storage"]


def _has_database(text: str) -> bool:
    return _has_any(text, ["rds", "database", "postgres", "postgresql", "mysql", "sql server", "aurora", "cosmos db", "dynamodb"])


def _has_storage(text: str) -> bool:
    return _has_any(text, ["s3", "bucket", "blob", "storage account", "object storage", "gcs"])


def _logging_missing(text: str) -> bool:
    negative_terms = [
        "no logging",
        "logging disabled",
        "monitoring is limited",
        "without monitoring",
        "without alerting",
    ]
    if _has_any(text, negative_terms):
        return True
    if _has_any(text, ["not configured", "not enabled"]) and _has_any(text, ["log", "logging", "monitor", "alert"]):
        return True
    return not _has_any(text, ["log", "logging", "monitor", "alert", "cloudtrail", "defender", "sentinel", "guardduty", "security command center"])


def _backup_missing(text: str) -> bool:
    if _has_any(text, ["no backup", "no backups", "without backups", "backup disabled"]):
        return True
    if _has_any(text, ["not documented", "not configured", "not enabled"]) and _has_any(text, ["backup", "backups", "snapshot", "restore"]):
        return True
    return not _has_any(text, ["backup", "snapshot", "restore", "point-in-time recovery", "replica"])


def _edge_protection_missing(text: str) -> bool:
    if _has_any(text, ["no waf", "without waf", "waf disabled", "no rate limit", "without rate limiting"]):
        return True
    if _has_any(text, ["not configured", "not enabled"]) and _has_any(text, ["waf", "rate limit", "ddos", "bot protection"]):
        return True
    return not _has_any(text, ["waf", "rate limit", "ddos", "bot protection"])


def _has_any(text: str, terms: List[str]) -> bool:
    return any(term in text for term in terms)


def _exposure(text: str, risky_terms: List[str]) -> str:
    return "Public or broad" if _has_any(text, risky_terms) else "Private or unspecified"


def _normalize(description: str) -> str:
    lowered = description.lower()
    return re.sub(r"\s+", " ", lowered).strip()


def _escape_md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
