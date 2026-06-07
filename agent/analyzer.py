from __future__ import annotations

import re
from dataclasses import replace
from typing import Iterable, List

from agent.schemas import AnalysisReport, Asset, AttackPath, Finding, RoadmapItem


SEVERITY_WEIGHTS = {
    "Critical": 35,
    "High": 15,
    "Medium": 7,
    "Low": 3,
}


def analyze_architecture(description: str) -> AnalysisReport:
    text = _normalize(description)
    assets = _detect_assets(text)
    findings = _detect_findings(text, assets)
    attack_paths = _build_attack_paths(text, findings, assets)
    risk_score = _score_findings(findings)
    risk_label = _risk_label(risk_score)
    score_drivers = _build_score_drivers(text, findings, risk_score)

    return AnalysisReport(
        architecture_summary=_summarize_architecture(text, assets, findings, risk_label),
        assets=assets,
        findings=findings,
        score_drivers=score_drivers,
        attack_paths=attack_paths,
        blast_radius=_estimate_blast_radius(text, assets, findings),
        fix_roadmap=_build_roadmap(text, findings),
        verification_checklist=_build_verification_checklist(text, findings),
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
            "### Score Drivers",
        ]
    )
    lines.extend([f"- {driver}" for driver in report.score_drivers])
    lines.append("")

    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.severity}: {finding.title}",
                f"- ID: `{finding.id}`",
                f"- Confidence: {finding.confidence}",
                f"- Affected assets: {', '.join(finding.affected_assets)}",
                f"- Evidence: {finding.evidence}",
                "",
                f"Why this matters: {finding.why_this_matters}",
                "",
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
    terms = _provider_terms(text)
    storage_sensitive_items = _storage_sensitive_data_items(text)
    database_sensitive_items = _database_sensitive_data_items(text)

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
                exposure=_exposure(text, ["public vm", "public ec2", "ssh open", "rdp open", "22 open", "3389 open", "management port"]),
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
                name=_database_asset_name(text),
                type="Data Store",
                exposure=_exposure(text, ["public database", "publicly accessible", "internet accessible", "0.0.0.0/0", "open to the internet"]),
                notes=(
                    f"Stores {_format_list(database_sensitive_items)}."
                    if database_sensitive_items
                    else f"Stores application data in {terms['database']} and may contain sensitive records."
                ),
            )
        )

    if _has_any(text, ["s3", "bucket", "blob", "storage account", "object storage", "gcs"]):
        assets.append(
            Asset(
                name=_storage_asset_name(text),
                type="Storage",
                exposure=_exposure(text, ["public bucket", "public-read", "anonymous", "world-readable", "public blob", "public access"]),
                notes=(
                    f"Stores {_format_list(storage_sensitive_items)}."
                    if storage_sensitive_items
                    else "Stores files, exports, logs, or customer content."
                ),
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

    if _has_container_platform(text):
        assets.append(
            Asset(
                name="Container platform",
                type="Container / Orchestration",
                exposure="Cluster managed",
                notes="Hosts containerized services and workload identities.",
            )
        )

    if _has_any(text, ["contractor", "contractors", "third party", "third-party", "external partner", "external users"]):
        assets.append(
            Asset(
                name="External contractor access path",
                type="External Access",
                exposure="Public storage access" if _contractor_public_access_pattern(text) else "Third-party access",
                notes="Provides non-employee access to shared data or application workflows.",
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
    terms = _provider_terms(text)
    public_storage = _has_public_storage(text)
    storage_sensitive_items = _storage_sensitive_data_items(text)
    database_sensitive_items = _database_sensitive_data_items(text)
    shared_env_key = _has_shared_env_key(text)
    data_access_logging_missing = _data_access_logging_missing(text)
    public_api = _has_public_api(text)

    if _has_database(text) and _has_any(text, ["public database", "publicly accessible", "internet accessible", "open to the internet", "0.0.0.0/0"]):
        findings.append(
            Finding(
                id="CSA-001",
                title=f"{terms['database']} appears directly reachable from the internet",
                severity="Critical",
                confidence="High",
                evidence=f"The description references {terms['database']} with public or 0.0.0.0/0 exposure.",
                impact="An attacker can attempt credential stuffing, exploit unpatched database services, or extract data if credentials are weak or leaked.",
                recommendation=f"Move {terms['database']} behind {terms['private_connectivity']}, restrict inbound access with {terms['network_rules']}, and require encrypted connections.",
                affected_assets=[_database_asset_name(text), "Cloud network controls"],
            )
        )

    if _has_storage(text) and public_storage:
        findings.append(
            Finding(
                id="CSA-002",
                title=f"{terms['storage_service']} allows public access",
                severity="High",
                confidence="High",
                evidence=_public_storage_evidence(text),
                impact="Anyone who discovers the endpoint may be able to retrieve accessible files without proving identity.",
                recommendation=f"Disable public {terms['storage_access']} at the account/container/bucket layer and use authenticated delivery patterns for approved users.",
                affected_assets=[_storage_asset_name(text)],
            )
        )

    if _has_storage(text) and storage_sensitive_items:
        findings.append(
            Finding(
                id="CSA-013",
                title=_sensitive_storage_title(text),
                severity="High" if public_storage else "Medium",
                confidence="High",
                evidence=f"The storage workflow contains {_format_list(storage_sensitive_items)}.",
                impact="Exposure of these exports can support targeted phishing, account enumeration, privacy incidents, and downstream customer support fraud.",
                recommendation="Classify the exports as sensitive, keep them private by default, minimize retained fields, and require approved identity-based access.",
                affected_assets=[_storage_asset_name(text)],
            )
        )

    if _has_database(text) and database_sensitive_items:
        findings.append(
            Finding(
                id="CSA-018",
                title=f"Sensitive data is stored in {_database_asset_name(text)}",
                severity="High" if "CSA-001" in [finding.id for finding in findings] else "Medium",
                confidence="High",
                evidence=f"The architecture says the application stores {_format_list(database_sensitive_items)} in {_database_asset_name(text)}.",
                impact=f"If the exposed data tier is compromised, an attacker can read or alter {_format_list(database_sensitive_items)} directly.",
                recommendation=f"Keep {terms['database']} private, encrypt and back up sensitive records, restrict application access, and monitor data-tier activity.",
                affected_assets=[_database_asset_name(text)],
            )
        )

    if shared_env_key:
        findings.append(
            Finding(
                id="CSA-014",
                title="Long-lived shared access key is copied into a local .env file",
                severity="High",
                confidence="High",
                evidence="The description says a shared access key is copied into a local .env file for scripts.",
                impact="Anyone who obtains the .env file can authenticate to storage within the key scope, enabling bulk download and possibly write or delete operations.",
                recommendation=f"Rotate the shared key, remove it from local files, and replace it with {terms['secret_replacement']}.",
                affected_assets=["Secrets and encryption keys", _storage_asset_name(text), "Cloud identity and permissions"],
            )
        )

    if _has_broad_database_ingress(text):
        findings.append(
            Finding(
                id="CSA-019",
                title="Broad inbound database access is exposed",
                severity="High",
                confidence="High",
                evidence=_broad_database_ingress_evidence(text),
                impact=_broad_database_ingress_impact(text),
                recommendation=_broad_database_ingress_recommendation(text),
                affected_assets=[_database_asset_name(text), "Cloud network controls"],
            )
        )

    if _has_storage(text) and data_access_logging_missing:
        findings.append(
            Finding(
                id="CSA-015",
                title=f"Logging and alerting for {terms['storage_read']} are not configured",
                severity="Medium",
                confidence="High",
                evidence=f"The description says logging and alerting for {terms['storage_read']} are not configured.",
                impact="A public or key-based download of customer exports could happen without timely detection, making incident scope and notification harder.",
                recommendation=f"Enable {terms['storage_service']} diagnostic logs for read operations, route them to {terms['monitoring']}, and alert on unusual read volume, anonymous reads, and access from unexpected locations.",
                affected_assets=[_storage_asset_name(text)],
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

    if _has_public_management_access(text):
        findings.append(
            Finding(
                id="CSA-005",
                title="Public management access is exposed",
                severity="High",
                confidence="High",
                evidence="The architecture references public SSH, RDP, admin ports, management ports, missing bastion access, port 22, port 3389, or remote desktop exposure.",
                impact="Attackers can scan, brute force, or exploit management services before reaching application controls.",
                recommendation=f"Remove public management ports, use a bastion or just-in-time access, and restrict {terms['network_rules']} to trusted sources.",
                affected_assets=["Compute workload", "Cloud network controls"],
            )
        )

    if _has_broad_application_ingress(text):
        findings.append(
            Finding(
                id="CSA-020",
                title="Broad inbound application access is exposed",
                severity="Medium",
                confidence="Medium",
                evidence="The architecture references broad public application ingress for web, HTTP, HTTPS, ALB, load balancer, or API traffic.",
                impact="The public application edge is intentionally reachable from the internet and should be protected against scanning, abuse, and exploit attempts.",
                recommendation=f"Keep only required application ports public, add {terms['waf']}, rate limiting, request logging, and alerting.",
                affected_assets=["Public application entry point", "Cloud network controls"],
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
                recommendation="Require phishing-resistant MFA for administrators and risk-based access controls for risky sign-ins.",
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

    if _logging_missing(text) and not data_access_logging_missing:
        findings.append(
            Finding(
                id="CSA-008",
                title="Detection and logging controls are not described",
                severity="Medium",
                confidence="Medium",
                evidence="The input does not mention audit logs, monitoring, alerting, or security telemetry.",
                impact="Compromise may go undetected, delaying containment and forensic investigation.",
                recommendation=f"Enable {terms['audit_logs']}, centralize security telemetry in {terms['monitoring']}, and alert on risky identity, network, and data events.",
                affected_assets=["Cloud identity and permissions", "Cloud network controls"],
            )
        )

    if _has_database(text) and _backup_missing(text):
        findings.append(
            Finding(
                id="CSA-009",
                title=f"{terms['database']} backup and recovery posture is not described",
                severity="Medium",
                confidence="Medium",
                evidence=f"{terms['database']} is present, but backups, snapshots, restore testing, or replicas are not mentioned.",
                impact="Ransomware, destructive changes, or operator error could become a prolonged outage or permanent data loss.",
                recommendation="Enable automated backups, test restores, and protect snapshots from accidental or malicious deletion.",
                affected_assets=[_database_asset_name(text)],
            )
        )

    if _has_any(text, ["public api", "api gateway", "internet-facing", "web app", "load balancer"]) and _edge_protection_missing(text):
        findings.append(
            Finding(
                id="CSA-010",
                title="Public application edge lacks described protective controls",
                severity="Medium",
                confidence="Medium",
                evidence=f"A public {terms['edge_service']} entry point is described, but {terms['waf']}, rate limiting, DDoS, or bot controls are not mentioned.",
                impact="The application is more exposed to commodity scanning, volumetric abuse, and simple exploit attempts.",
                recommendation=f"Add {terms['waf']} protections, request rate limits, managed DDoS protection, and application-layer alerting.",
                affected_assets=["Public application entry point"],
            )
        )

    if public_api and _has_storage(text):
        findings.append(
            Finding(
                id="CSA-016",
                title="Public API is connected to the storage workflow",
                severity="Medium",
                confidence="Medium",
                evidence=f"The description places a public {terms['edge_service']} in the same workflow as {terms['storage_service']}.",
                impact="The public API becomes a discovery and abuse surface for storage-backed workflows, especially if rate limiting, WAF rules, and downstream authorization are weak.",
                recommendation=f"Protect the API with authentication, authorization, {terms['waf']} rules, rate limits, request logging, and least-privilege {terms['storage_service']} access from the application.",
                affected_assets=["Public application entry point", _storage_asset_name(text)],
            )
        )

    if _contractor_public_access_pattern(text):
        findings.append(
            Finding(
                id="CSA-017",
                title="Contractor access relies on public storage instead of controlled identity",
                severity="Medium",
                confidence="High",
                evidence=f"The description says public {terms['storage_access']} is enabled so contractors can download files without VPN access.",
                impact="Convenience access removes identity proof, user-level accountability, and easy revocation for contractor downloads.",
                recommendation=f"Move contractor access to a controlled path such as {terms['contractor_identity_options']}.",
                affected_assets=[_storage_asset_name(text), "External contractor access path"],
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

    return [replace(finding, why_this_matters=_why_this_matters(text, finding)) for finding in _dedupe_findings(findings)]


def _build_attack_paths(text: str, findings: List[Finding], assets: List[Asset]) -> List[AttackPath]:
    finding_ids = {finding.id for finding in findings}
    terms = _provider_terms(text)
    storage_sensitive_items = _storage_sensitive_data_items(text)
    database_sensitive_items = _database_sensitive_data_items(text)
    paths: List[AttackPath] = []

    if "CSA-001" in finding_ids and "CSA-019" in finding_ids:
        data_target = _format_list(database_sensitive_items or _sensitive_data_items(text))
        paths.append(
            AttackPath(
                name="Public application edge to exposed data tier",
                difficulty="Low to Medium",
                steps=_public_edge_to_data_tier_steps(text, data_target),
                impact=f"Direct exposure of {data_target} through a reachable data-tier listener.",
                blocked_by=_broad_database_ingress_recommendation(text),
            )
        )
    elif "CSA-001" in finding_ids:
        data_target = _format_list(database_sensitive_items or _sensitive_data_items(text))
        paths.append(
            AttackPath(
                name=f"Internet to exposed {terms['database']}",
                difficulty="Low to Medium",
                steps=[
                    f"Attacker scans cloud IP ranges or DNS records for reachable {terms['database']} ports.",
                    "Attacker attempts password spraying, credential reuse, or known service exploits.",
                    f"Attacker reads or modifies {data_target} directly, bypassing the application tier.",
                ],
                impact=f"Direct compromise of {data_target} and potential destructive data changes.",
                blocked_by=f"Private {terms['database']} networking, restrictive {terms['network_rules']}, strong authentication, and data-tier activity monitoring.",
            )
        )

    if "CSA-002" in finding_ids and "CSA-013" in finding_ids:
        exposed_items = _format_list(storage_sensitive_items or _sensitive_data_items(text))
        paths.append(
            AttackPath(
                name="Public storage discovery to customer export exposure",
                difficulty="Low",
                steps=[
                    f"Attacker discovers the public {terms['edge_service']}, contractor download path, or {terms['storage_service']} endpoint through DNS, application traffic, shared links, or naming patterns.",
                    f"Attacker reaches anonymous {terms['storage_access']} because public storage access is enabled.",
                    f"Attacker downloads customer exports through accessible {terms['storage_object_plural']}.",
                    f"Attacker extracts {exposed_items} from the exports.",
                    "Attacker uses the identifiers and support context for phishing, account targeting, social engineering, or follow-on compromise.",
                ],
                impact="Customer data disclosure with a credible path to targeted abuse beyond the initial storage download.",
                blocked_by=f"Disable public {terms['storage_access']}, require authenticated contractor access, minimize export fields, and alert on unusual {terms['storage_read']}.",
            )
        )
    elif "CSA-002" in finding_ids:
        paths.append(
            AttackPath(
                name="Public storage to data exposure",
                difficulty="Low",
                steps=[
                    f"Attacker discovers public {terms['storage_service']} through search, logs, source code, or naming patterns.",
                    f"Attacker lists or downloads accessible {terms['storage_object_plural']}.",
                    "Attacker uses exposed files, backups, or logs to identify customers, credentials, or internal services.",
                ],
                impact="Sensitive data disclosure and possible follow-on credential compromise.",
                blocked_by=f"Public access blocks, {terms['private_endpoint']}, least-privilege storage policies, and {terms['storage_read']} alerts.",
            )
        )

    if "CSA-014" in finding_ids:
        paths.append(
            AttackPath(
                name="Leaked .env access key to authenticated storage abuse",
                difficulty="Low to Medium",
                steps=[
                    "Attacker obtains the local .env file from a developer workstation, shared script folder, backup, or accidental repository exposure.",
                    f"Attacker uses the shared access key to authenticate to {terms['storage_service']}.",
                    f"Attacker enumerates the key scope and accessible {terms['storage_object_plural']}.",
                    "Attacker performs bulk export download, and if the key allows writes or deletes, may alter or destroy stored objects.",
                ],
                impact="Authenticated data extraction or destructive storage operations across every resource the shared key can reach.",
                blocked_by=f"Rotate the shared key, remove .env secrets, use {terms['secret_replacement']}, and monitor storage-key authentication.",
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
    terms = _provider_terms(text)
    storage_sensitive_items = _storage_sensitive_data_items(text)
    database_sensitive_items = _database_sensitive_data_items(text)
    sensitive_items = _sensitive_data_items(text)
    radius: List[str] = []

    if "CSA-001" in finding_ids or "CSA-009" in finding_ids:
        data_items = _format_list(database_sensitive_items or sensitive_items)
        radius.append(f"Data tier risk: {data_items}, backups, and {terms['database']} availability may be affected.")

    if "CSA-002" in finding_ids:
        radius.append(f"Storage risk: all {terms['storage_object_plural']} reachable through public {terms['storage_access']} may be downloadable by anyone who discovers the storage URL.")

    if "CSA-013" in finding_ids:
        radius.append(f"Customer data risk: the described exports include {_format_list(storage_sensitive_items or sensitive_items)} that can be used for phishing, account targeting, and social engineering.")

    if "CSA-018" in finding_ids and "CSA-001" not in finding_ids:
        radius.append(f"Sensitive data risk: {_format_list(database_sensitive_items or sensitive_items)} is in the data tier and should be protected with least-privilege access, encryption, backups, and monitoring.")

    if "CSA-014" in finding_ids:
        radius.append(f"Shared key risk: all {terms['storage_scope']} and operations within the shared access key scope may be exposed to bulk extraction or destructive operations.")

    if "CSA-019" in finding_ids:
        radius.append(f"Database ingress risk: PostgreSQL traffic from the internet can reach {_database_asset_name(text)}, increasing the chance of direct credential attacks or database-service exploitation.")

    if "CSA-003" in finding_ids or "CSA-004" in finding_ids:
        radius.append("Identity-plane risk: overprivileged credentials could affect multiple services, environments, or cloud resources.")

    if "CSA-005" in finding_ids:
        radius.append("Network risk: exposed management paths can allow direct administrative targeting and potential lateral movement beyond the first workload.")
    elif "CSA-011" in finding_ids:
        radius.append("Network risk: weak segmentation can allow lateral movement beyond the first workload.")

    if "CSA-015" in finding_ids:
        radius.append(f"Detection risk: {terms['storage_read']} are not logged or alerted, so unusual data downloads may not be noticed quickly.")
    elif "CSA-008" in finding_ids:
        radius.append("Detection risk: incident scope may be hard to prove because audit, monitoring, or alert coverage is not described.")

    if "CSA-016" in finding_ids:
        radius.append(f"Public API risk: the {terms['edge_service']} may provide a visible entry point for discovering or abusing the storage-backed workflow.")

    if not radius:
        radius.append("Blast radius cannot be confidently estimated without more detail about data sensitivity, identity scope, and network boundaries.")

    radius.append(f"Assets considered in scope: {', '.join(asset.name for asset in assets)}.")
    return radius


def _build_roadmap(text: str, findings: List[Finding]) -> List[RoadmapItem]:
    finding_ids = {finding.id for finding in findings}
    terms = _provider_terms(text)
    roadmap: List[RoadmapItem] = []

    if _is_aws_rds_postgres_exposure(text, finding_ids):
        roadmap.append(
            RoadmapItem(
                priority="P0",
                action="Disable public accessibility on RDS and remove 0.0.0.0/0 from PostgreSQL Security Group ingress.",
                expected_outcome="Immediately removes direct internet reachability to the PostgreSQL listener.",
            )
        )
    elif "CSA-002" in finding_ids and "CSA-014" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P0",
                action=f"Disable public {terms['storage_access']}, review storage policies, rotate the shared access key, and remove the key from local .env files.",
                expected_outcome="Stops both anonymous storage downloads and authenticated abuse through the leaked shared key.",
            )
        )
    elif "CSA-002" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P0",
                action=f"Disable public {terms['storage_access']} and review all storage policies.",
                expected_outcome="Prevents anonymous retrieval of exposed objects.",
            )
        )
    elif "CSA-014" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P0",
                action="Rotate the shared access key, remove it from local .env files, and invalidate any copies used by scripts.",
                expected_outcome="Removes a long-lived credential that could enable authenticated storage extraction.",
            )
        )
    elif "CSA-001" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P0",
                action=f"Remove direct public {terms['database']} access and allow only the application tier over required ports.",
                expected_outcome="Eliminates the highest-risk direct data-store attack path.",
            )
        )
    else:
        roadmap.append(
            RoadmapItem(
                priority="P0",
                action="Confirm no data stores, credentials, or administrative endpoints are publicly exposed beyond intended design.",
                expected_outcome="Establishes immediate containment for the highest-risk asset paths.",
            )
        )

    if _is_aws_rds_postgres_exposure(text, finding_ids):
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action="Move RDS into private subnets and allow PostgreSQL only from the EC2 application Security Group.",
                expected_outcome="Restores the intended application-to-database trust boundary.",
            )
        )
    elif "CSA-017" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action=f"Replace contractor public access with {terms['contractor_identity_options']}.",
                expected_outcome="Contractors retain approved access while identity, expiry, scope, and revocation are enforced.",
            )
        )
    elif "CSA-003" in finding_ids or "CSA-004" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action="Rotate exposed credentials and replace broad IAM grants with least-privilege roles.",
                expected_outcome="Limits the impact of credential theft and reduces control-plane blast radius.",
            )
        )
    elif "CSA-005" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action="Close public management ports and move administration behind bastion or just-in-time access.",
                expected_outcome="Reduces internet-facing footholds and brute-force opportunities.",
            )
        )
    elif "CSA-019" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action=_broad_database_ingress_recommendation(text),
                expected_outcome="Reduces direct internet reachability to the data tier while preserving approved application access.",
            )
        )
    elif "CSA-012" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action="Require authentication and authorization for sensitive API operations.",
                expected_outcome="Stops anonymous access to application functions and data.",
            )
        )
    else:
        roadmap.append(
            RoadmapItem(
                priority="P1",
                action="Tighten identity and access patterns for users, services, and third parties.",
                expected_outcome="Reduces the chance that one exposed path becomes broader compromise.",
            )
        )

    if _is_aws_rds_postgres_exposure(text, finding_ids):
        roadmap.append(
            RoadmapItem(
                priority="P2",
                action="Enable CloudTrail, CloudWatch alerts, ALB or API Gateway request logging, AWS WAF protections, rate limiting, GuardDuty, and VPC Flow Logs where available.",
                expected_outcome="Improves detection of public-edge abuse, control-plane changes, and suspicious network activity.",
            )
        )
    elif "CSA-015" in finding_ids:
        roadmap.append(
            RoadmapItem(
                priority="P2",
                action=f"Enable {terms['storage_read']} logs, {terms['monitoring']}, alerts for unusual storage reads, API request logging, {terms['waf']} protections, and rate limiting.",
                expected_outcome="Improves detection of data extraction and reduces abuse of the public API edge.",
            )
        )
    elif any(finding_id in finding_ids for finding_id in ["CSA-008", "CSA-010", "CSA-016"]):
        roadmap.append(
            RoadmapItem(
                priority="P2",
                action=f"Enable {terms['audit_logs']}, {terms['monitoring']} alerts, {terms['edge_service']} request logging, {terms['waf']} protections, rate limiting, {terms['threat_detection']}, and {terms['flow_logs']} where available.",
                expected_outcome="Improves detection of public-edge abuse, control-plane changes, and suspicious network activity.",
            )
        )
    elif any(finding_id in finding_ids for finding_id in ["CSA-006", "CSA-007", "CSA-009", "CSA-011"]):
        roadmap.append(
            RoadmapItem(
                priority="P2",
                action="Harden baseline controls: MFA, encryption, backups, segmentation, logging, and alerting.",
                expected_outcome="Improves resilience, detection, and containment across the environment.",
            )
        )
    else:
        roadmap.append(
            RoadmapItem(
                priority="P2",
                action="Add monitoring and validation for the most important identity, network, storage, and application events.",
                expected_outcome="Makes future abuse easier to detect and investigate.",
            )
        )

    roadmap.append(
        RoadmapItem(
            priority="P3",
            action=(
                "Test RDS backup/restore, document the target architecture, run a tabletop review, and re-run CloudSec Atlas."
                if _is_aws_rds_postgres_exposure(text, finding_ids)
                else "Run a tabletop review of the attack paths, document the target architecture, and re-run CloudSec Atlas after fixes."
            ),
            expected_outcome="Confirms the risk chain is broken and turns remediation into repeatable verification.",
        )
    )

    return roadmap


def _build_verification_checklist(text: str, findings: List[Finding]) -> List[str]:
    terms = _provider_terms(text)
    sensitive_items = _sensitive_data_items(text)
    storage_sensitive_items = _storage_sensitive_data_items(text)
    database_sensitive_items = _database_sensitive_data_items(text)
    checklist = [
        "Confirm all public endpoints are intentionally exposed and protected by edge controls.",
        f"Validate that {terms['audit_logs']} are enabled and routed to {terms['monitoring']}.",
        f"Review {terms['identity_review_subject']} for least privilege, resource scoping, and removal of wildcard permissions.",
    ]

    finding_ids = {finding.id for finding in findings}
    if "CSA-001" in finding_ids:
        checklist.append(f"Verify {terms['database']} is private and reachable only from approved application subnets or services.")
    if "CSA-002" in finding_ids:
        checklist.append(f"Confirm public {terms['storage_access']} is disabled at the account/container/bucket layer.")
        checklist.append("Run storage public-access checks and confirm anonymous reads are blocked.")
    if "CSA-013" in finding_ids:
        checklist.append(f"Confirm {_format_list(storage_sensitive_items or sensitive_items)} are classified, minimized, and stored only in private locations.")
    if "CSA-018" in finding_ids:
        checklist.append(f"Confirm {_format_list(database_sensitive_items or sensitive_items)} are protected in {terms['database']} with least-privilege access and data-tier monitoring.")
    if "CSA-019" in finding_ids:
        checklist.append(_broad_database_ingress_recommendation(text))
    if "CSA-014" in finding_ids:
        checklist.append("Confirm shared access keys are rotated and old keys are invalidated.")
        checklist.append("Confirm the .env secret is removed from local scripts, repositories, backups, and shared folders.")
        checklist.append(f"Confirm {terms['secret_replacement']} are used instead of long-lived shared keys.")
    if "CSA-003" in finding_ids or "CSA-004" in finding_ids:
        checklist.append("Rotate suspected credentials and confirm no long-lived secrets remain in code or plaintext stores.")
    if "CSA-015" in finding_ids:
        checklist.append(f"Confirm {terms['storage_read']} logs are enabled and routed to {terms['monitoring']} or a SIEM.")
        checklist.append(f"Confirm alerts fire for unusual {terms['storage_read']}, anonymous reads, high-volume downloads, and unexpected source locations.")
    if "CSA-017" in finding_ids:
        checklist.append(f"Test contractor access through the approved secure path and confirm public {terms['storage_access']} is no longer required.")
    if "CSA-005" in finding_ids:
        checklist.append(f"Scan {terms['network_rules']} for public SSH, RDP, and management ports.")
    if "CSA-007" in finding_ids:
        checklist.append("Confirm encryption at rest and in transit for data stores, storage, backups, and service traffic.")
    if "CSA-009" in finding_ids:
        checklist.append(f"Perform a restore test from the latest {terms['database']} backup or snapshot.")

    checklist.append("Re-run CloudSec Atlas after remediation and confirm critical and high findings are cleared.")
    return checklist


def _build_target_architecture(text: str, assets: List[Asset], findings: List[Finding]) -> List[str]:
    terms = _provider_terms(text)
    target = [
        f"Use a public edge layer only where required, protected by {terms['waf']}, rate limiting, TLS, and request logging.",
        "Place application workloads in private subnets or managed private runtimes with explicit outbound paths.",
        "Keep data stores private, encrypted, backed up, and reachable only from approved workloads.",
        f"Use {terms['identity_options']} with least-privilege permissions and MFA for administrators.",
        f"Centralize {terms['audit_logs']}, security telemetry, and alerts in {terms['monitoring']} for identity, network, storage, and data access events.",
    ]

    if _has_storage(text):
        target.append(f"Serve private {terms['storage_service']} through {terms['private_storage_delivery']}.")
    if _contractor_public_access_pattern(text):
        target.append("Give contractors access through an approved identity-aware path with expiry, least privilege, user-level auditability, and easy revocation.")
    if _has_shared_env_key(text):
        target.append(f"Use {terms['secret_replacement']} instead of shared access keys copied into local .env files.")
    if _has_database(text):
        target.append(f"Add tested {terms['database']} recovery with point-in-time restore, protected snapshots, and deletion safeguards.")
    if _has_container_platform(text):
        target.append("Constrain workload identity, network policies, admission controls, and image provenance for container workloads.")

    return target


def _summarize_architecture(text: str, assets: List[Asset], findings: List[Finding], risk_label: str) -> str:
    provider = _detect_provider(text)
    article = "an" if provider in {"AWS", "Azure"} else "a"
    asset_types = ", ".join(sorted({asset.type for asset in assets}))
    finding_ids = {finding.id for finding in findings}
    terms = _provider_terms(text)
    storage_sensitive_items = _storage_sensitive_data_items(text)
    database_sensitive_items = _database_sensitive_data_items(text)
    top_findings = [finding.title for finding in findings if finding.severity in {"Critical", "High"}]

    if "CSA-002" in finding_ids and "CSA-013" in finding_ids:
        risk_sentence = (
            f"The key risk chain is public {terms['storage_service']} leading to exposed data that includes "
            f"{_format_list(storage_sensitive_items or _sensitive_data_items(text))}."
        )
        if "CSA-015" in finding_ids:
            risk_sentence += f" Missing logging and alerting for {terms['storage_read']} make that exposure harder to detect."
        if "CSA-014" in finding_ids:
            risk_sentence += " The shared access key in a local .env file creates a second authenticated extraction path."
    elif "CSA-001" in finding_ids and "CSA-018" in finding_ids:
        risk_sentence = (
            f"The key risk chain is direct internet reachability to {terms['database']}, "
            f"where the application stores {_format_list(database_sensitive_items or _sensitive_data_items(text))}."
        )
    elif top_findings:
        risk_sentence = f"The most important risks are: {', '.join(top_findings[:3])}."
    else:
        risk_sentence = "No explicit critical or high-risk rule match was found, but the design still needs configuration validation."

    return (
        f"The submitted design appears to describe {article} {provider} cloud environment with "
        f"{len(assets)} detected asset area(s): {asset_types}. CloudSec Atlas rates the current "
        f"posture as {risk_label}. {risk_sentence} {_score_driver_sentence(finding_ids)}"
    )


def _detect_provider(text: str) -> str:
    provider_key = _detect_provider_key(text)
    if provider_key == "aws":
        return "AWS"
    if provider_key == "azure":
        return "Azure"
    return "provider-neutral"


def _detect_provider_key(text: str) -> str:
    aws_terms = [
        "aws",
        "ec2",
        "rds",
        "s3",
        "iam",
        "alb",
        "vpc",
        "cloudtrail",
        "cloudwatch",
        "security group",
        "security groups",
        "lambda",
        "guardduty",
        "aurora",
        "dynamodb",
    ]
    azure_terms = [
        "azure",
        "app service",
        "blob storage",
        "blob",
        "entra id",
        "nsg",
        "key vault",
        "azure monitor",
        "defender for cloud",
        "managed identity",
        "storage account",
    ]

    if _has_any(text, aws_terms):
        return "aws"
    if _has_any(text, azure_terms):
        return "azure"
    return "generic"


def _provider_terms(text: str) -> dict:
    provider_key = _detect_provider_key(text)
    terms = {
        "aws": {
            "storage_service": "Amazon S3",
            "storage_access": "S3 bucket/object access",
            "storage_read": "S3 object reads",
            "storage_object_plural": "S3 objects",
            "storage_scope": "S3 buckets and objects",
            "database": "RDS" if "rds" in text else "database",
            "network_rules": "Security Groups and NACLs",
            "edge_service": "ALB or API Gateway",
            "waf": "AWS WAF",
            "audit_logs": "CloudTrail logs",
            "monitoring": "CloudWatch",
            "threat_detection": "GuardDuty",
            "flow_logs": "VPC Flow Logs",
            "private_endpoint": "VPC endpoints or private subnets",
            "private_connectivity": "private subnets",
            "contractor_identity_options": "pre-signed URLs, IAM Identity Center, federated identity, IAM roles, temporary STS credentials, or an authenticated portal",
            "secret_replacement": "AWS Secrets Manager, IAM roles, or temporary STS credentials",
            "identity_options": "IAM Identity Center, federated identity, IAM roles, or temporary STS credentials",
            "identity_review_subject": "IAM roles and policies",
            "private_storage_delivery": "pre-signed URLs, IAM roles, temporary STS credentials, CloudFront origin access controls, or authenticated application flows",
        },
        "azure": {
            "storage_service": "Azure Blob Storage",
            "storage_access": "blob access",
            "storage_read": "blob reads",
            "storage_object_plural": "blobs",
            "storage_scope": "containers and blobs",
            "database": "database",
            "network_rules": "NSGs",
            "edge_service": "App Service API",
            "waf": "Azure WAF",
            "audit_logs": "Azure activity logs",
            "monitoring": "Azure Monitor",
            "threat_detection": "Defender for Cloud",
            "flow_logs": "NSG flow logs",
            "private_endpoint": "Private Endpoints",
            "private_connectivity": "Private Endpoints or private networking",
            "contractor_identity_options": "Entra ID, signed URLs, short-lived scoped SAS tokens, Private Endpoints, or an authenticated portal",
            "secret_replacement": "managed identity, Key Vault, or narrowly scoped short-lived SAS tokens",
            "identity_options": "managed identities, Entra ID, or short-lived scoped SAS tokens",
            "identity_review_subject": "managed identities, Entra ID assignments, and role assignments",
            "private_storage_delivery": "signed URLs, scoped temporary SAS tokens, Entra ID, CDN origin access controls, or authenticated application flows",
        },
        "generic": {
            "storage_service": "object storage",
            "storage_access": "object storage access",
            "storage_read": "object reads",
            "storage_object_plural": "objects",
            "storage_scope": "storage containers, buckets, and objects",
            "database": "database",
            "network_rules": "network firewall rules",
            "edge_service": "public API",
            "waf": "managed WAF",
            "audit_logs": "cloud audit logs",
            "monitoring": "central monitoring",
            "threat_detection": "cloud threat detection",
            "flow_logs": "network flow logs",
            "private_endpoint": "private endpoints",
            "private_connectivity": "private networking",
            "contractor_identity_options": "signed URLs, federated identity, temporary scoped credentials, private endpoints, or an authenticated portal",
            "secret_replacement": "managed identities, a managed secret store, or short-lived scoped credentials",
            "identity_options": "federated identity, managed identities, or short-lived scoped credentials",
            "identity_review_subject": "cloud identities, roles, and policies",
            "private_storage_delivery": "signed URLs, federated identity, private endpoints, CDN origin access controls, or authenticated application flows",
        },
    }
    return terms[provider_key]


def _database_asset_name(text: str) -> str:
    if "rds" in text and _has_any(text, ["postgres", "postgresql"]):
        return "RDS PostgreSQL database"
    if "rds" in text:
        return "RDS database"
    if _detect_provider_key(text) == "azure":
        return "Azure database"
    return "Application database"


def _storage_asset_name(text: str) -> str:
    provider_key = _detect_provider_key(text)
    if provider_key == "aws":
        return "Amazon S3 storage"
    if provider_key == "azure":
        return "Azure Blob Storage"
    return "Object storage"


def _score_findings(findings: List[Finding]) -> int:
    finding_ids = {finding.id for finding in findings}
    score = sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)

    if "CSA-002" in finding_ids and "CSA-013" in finding_ids:
        score += 5
        score = max(score, 50)

    if "CSA-002" in finding_ids and "CSA-013" in finding_ids and ("CSA-015" in finding_ids or "CSA-008" in finding_ids):
        score += 4
        score = max(score, 65)

    if "CSA-014" in finding_ids:
        score += 4

    if "CSA-016" in finding_ids and "CSA-002" in finding_ids:
        score += 3

    if "CSA-001" in finding_ids and ("CSA-019" in finding_ids or "CSA-005" in finding_ids):
        score += 15

    if "CSA-003" in finding_ids and "CSA-004" in finding_ids:
        score += 5

    return min(100, max(0, score))


def _build_score_drivers(text: str, findings: List[Finding], risk_score: int) -> List[str]:
    finding_ids = {finding.id for finding in findings}

    if _is_aws_rds_postgres_exposure(text, finding_ids):
        return [
            "Public RDS exposure: +40",
            "Sensitive customer data in exposed data tier: +25",
            "Broad PostgreSQL ingress from 0.0.0.0/0: +20",
            "Missing WAF and recovery evidence: +9",
        ]

    if "CSA-002" in finding_ids and "CSA-013" in finding_ids:
        drivers = [
            "Public storage exposure: +25",
            "Sensitive data in exposed storage workflow: +20",
        ]
        if "CSA-014" in finding_ids:
            drivers.append("Shared access key or local .env secret: +18")
        if "CSA-015" in finding_ids:
            drivers.append("Missing storage read logging and alerting: +12")
        if "CSA-016" in finding_ids or "CSA-017" in finding_ids:
            drivers.append("Public API or weak contractor access path: +14")
        return drivers

    if "CSA-003" in finding_ids or "CSA-004" in finding_ids:
        drivers = []
        if "CSA-003" in finding_ids:
            drivers.append("Overprivileged identity permissions: +25")
        if "CSA-004" in finding_ids:
            drivers.append("Secrets stored in code or plaintext: +20")
        if "CSA-006" in finding_ids:
            drivers.append("Missing MFA for privileged access: +10")
        if "CSA-008" in finding_ids:
            drivers.append("Limited detection and audit evidence: +10")
        if "CSA-010" in finding_ids:
            drivers.append("Public edge controls not described: +5")
        return drivers

    return [f"Matched deterministic security findings total: {risk_score}/100"]


def _risk_label(score: int) -> str:
    if score >= 90:
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


def _has_broad_database_ingress(text: str) -> bool:
    if not _has_database(text):
        return False

    database_terms = ["rds", "database", "postgres", "postgresql", "mysql", "sql server", "aurora"]
    broad_terms = ["0.0.0.0/0", "any source", "anywhere", "from the internet", "open to the internet"]
    rule_terms = ["security group", "nsg", "firewall", "ingress", "inbound", "allows", "allow"]

    return _has_any(text, broad_terms) and _has_any(text, database_terms) and _has_any(text, rule_terms)


def _broad_database_ingress_evidence(text: str) -> str:
    if _detect_provider_key(text) == "aws" and "rds" in text and _has_any(text, ["postgres", "postgresql"]) and "security group" in text and "0.0.0.0/0" in text:
        return "The RDS security group allows PostgreSQL traffic from 0.0.0.0/0."
    if _has_any(text, ["postgres", "postgresql"]) and "0.0.0.0/0" in text:
        return "The database network rule allows PostgreSQL traffic from 0.0.0.0/0."
    return "The database ingress rule allows traffic from a broad internet source."


def _broad_database_ingress_impact(text: str) -> str:
    if _has_any(text, ["postgres", "postgresql"]):
        return "Attackers can directly target the PostgreSQL listener from the internet, increasing exposure to password spraying, credential reuse, and database-service exploitation."
    return "Attackers can directly target the database listener from the internet, increasing exposure to password spraying, credential reuse, and database-service exploitation."


def _broad_database_ingress_recommendation(text: str) -> str:
    if _detect_provider_key(text) == "aws" and _has_any(text, ["postgres", "postgresql"]):
        return "Restrict PostgreSQL ingress to approved application Security Groups or private subnets only."
    terms = _provider_terms(text)
    return f"Restrict database ingress to approved application {terms['network_rules']} or private subnets only."


def _is_aws_rds_postgres_exposure(text: str, finding_ids) -> bool:
    return (
        _detect_provider_key(text) == "aws"
        and "rds" in text
        and _has_any(text, ["postgres", "postgresql"])
        and "CSA-001" in finding_ids
        and "CSA-019" in finding_ids
    )


def _why_this_matters(text: str, finding: Finding) -> str:
    terms = _provider_terms(text)
    finding_id = finding.id
    storage_items = _storage_sensitive_data_items(text)
    database_items = _database_sensitive_data_items(text)
    sensitive_items = _sensitive_data_items(text)
    data_text = _format_list(database_items or storage_items or sensitive_items)

    if finding_id == "CSA-001":
        if _detect_provider_key(text) == "aws" and "rds" in text and _has_any(text, ["postgres", "postgresql"]):
            return "A public RDS endpoint bypasses the normal application security layer. Even if the web app is protected, attackers can directly target PostgreSQL using credential reuse, password spraying, or database-service exploitation."
        return f"A public {terms['database']} endpoint bypasses the application security layer and lets attackers target the data service directly."

    if finding_id == "CSA-019":
        return "The Security Group rule makes PostgreSQL reachable from any internet source. That turns the database listener itself into an attack surface instead of limiting database access to the EC2 application tier."

    if finding_id == "CSA-018":
        return f"The exposed data tier contains {data_text}. If RDS is reachable from the internet, compromise affects customer data directly rather than only the web application."

    if finding_id == "CSA-009":
        return "The architecture describes sensitive records in RDS but does not prove restore readiness. Without tested recovery, a destructive database event can become both a data-loss incident and an extended outage."

    if finding_id == "CSA-010":
        return f"The architecture has an internet-facing application edge, but no {terms['waf']} or rate-limit evidence. That leaves the public entry point easier to scan, abuse, and use as reconnaissance for the exposed data tier."

    if finding_id == "CSA-002":
        return f"Public {terms['storage_access']} removes the identity check in front of stored data. Anyone who discovers the storage URL can try to retrieve accessible {terms['storage_object_plural']}."

    if finding_id == "CSA-013":
        return f"The storage workflow contains {_format_list(storage_items or sensitive_items)}. If public access remains enabled, the exposure can turn from a configuration issue into customer-data disclosure."

    if finding_id == "CSA-014":
        return f"A shared key in a local .env file creates a reusable credential outside normal identity controls. If copied or leaked, it can grant authenticated access to {terms['storage_service']} within the key scope."

    if finding_id == "CSA-015":
        return f"Missing logs and alerts for {terms['storage_read']} means data extraction may not be noticed quickly. That weakens containment and makes incident scoping harder."

    if finding_id == "CSA-003":
        return "Overprivileged identity permissions make one credential compromise more damaging. An attacker can move from a single role or user into broad cloud control-plane access."

    if finding_id == "CSA-004":
        return "Secrets in code or plaintext are easy to copy, sync, or leak. Once exposed, they can turn a source-code or workstation issue into authenticated cloud access."

    if finding_id == "CSA-005":
        return "Public management access exposes administrative protocols before normal application controls. Attackers can target SSH, RDP, or admin services directly."

    if finding_id == "CSA-020":
        return "Broad application ingress may be intentional, but it still needs edge controls. Without request filtering and rate limits, the application is easier to scan and abuse."

    if finding_id == "CSA-006":
        return "Without MFA on privileged access, stolen passwords or tokens are more likely to become successful administrative sessions."

    if finding_id == "CSA-007":
        return "Missing encryption increases the impact of copied storage, snapshots, backups, or intercepted service traffic."

    if finding_id == "CSA-008":
        return "The architecture does not show enough telemetry to prove what happened after an incident. That slows detection, containment, and forensic review."

    if finding_id == "CSA-016":
        return f"The public API is part of the same workflow as {terms['storage_service']}. If authorization or rate limiting is weak, the API can help attackers discover or abuse storage-backed operations."

    if finding_id == "CSA-017":
        return "Contractor access through public storage trades identity and revocation for convenience. That makes it harder to prove who accessed data and harder to shut off access cleanly."

    if finding_id == "CSA-011":
        return "Weak segmentation makes the first compromised workload more valuable. A foothold can reach data stores or identity-adjacent services that should be isolated."

    if finding_id == "CSA-012":
        return "Unauthenticated application access lets attackers interact with sensitive functions without a trusted user context."

    return "The input does not provide enough control evidence to prove this risk is contained, so the architecture needs a focused configuration review."


def _public_edge_to_data_tier_steps(text: str, data_target: str) -> List[str]:
    if _detect_provider_key(text) == "aws" and "rds" in text and _has_any(text, ["postgres", "postgresql"]):
        return [
            "Attacker finds the internet-facing application and associated infrastructure.",
            "Attacker identifies reachable PostgreSQL/RDS exposure or obtains database credentials through leakage or reuse.",
            "Attacker connects directly to the public RDS endpoint.",
            f"Attacker reads or modifies {data_target}.",
        ]

    terms = _provider_terms(text)
    return [
        "Attacker finds the internet-facing application and associated infrastructure.",
        f"Attacker identifies reachable {terms['database']} exposure or obtains database credentials through leakage or reuse.",
        f"Attacker connects directly to the public {terms['database']} endpoint.",
        f"Attacker reads or modifies {data_target}.",
    ]


def _has_public_management_access(text: str) -> bool:
    management_terms = [
        "ssh",
        "rdp",
        "admin port",
        "management port",
        "bastion missing",
        "missing bastion",
        "remote desktop",
    ]
    return _has_any(text, management_terms) or bool(re.search(r"\b(22|3389)\b", text))


def _has_broad_application_ingress(text: str) -> bool:
    app_terms = ["http", "https", "web", "web app", "public api", "api gateway", "alb", "load balancer", "application load balancer"]
    broad_terms = ["0.0.0.0/0", "any source", "from the internet"]

    if not _has_any(text, app_terms) or not _has_any(text, broad_terms):
        return False

    return any(_phrase_near_any(text, app_term, broad_terms, window=90) for app_term in app_terms)


def _has_database(text: str) -> bool:
    return _has_any(text, ["rds", "database", "postgres", "postgresql", "mysql", "sql server", "aurora", "cosmos db", "dynamodb"])


def _has_storage(text: str) -> bool:
    return _has_any(text, ["s3", "bucket", "blob", "storage account", "object storage", "gcs"])


def _has_container_platform(text: str) -> bool:
    return _has_any(
        text,
        [
            "kubernetes",
            "aks",
            "eks",
            "gke",
            "container platform",
            "container cluster",
            "containerized",
            "container workload",
            "docker",
        ],
    )


def _has_public_storage(text: str) -> bool:
    return _has_any(
        text,
        [
            "public bucket",
            "public-read",
            "anonymous",
            "world-readable",
            "public blob",
            "public access",
            "public blob access",
            "container has public",
            "public container",
        ],
    )


def _public_storage_evidence(text: str) -> str:
    terms = _provider_terms(text)
    if "public bucket" in text or "public-read" in text:
        return f"The description references public {terms['storage_access']}."
    if "public blob access enabled" in text:
        return "The description says the storage container has public blob access enabled."
    if "public access" in text and "storage" in text:
        return f"The description says public access is enabled for {terms['storage_service']}."
    if "anonymous" in text:
        return "The description references anonymous access to object storage."
    if "world-readable" in text:
        return "The description references world-readable object storage."
    return f"The description says {terms['storage_service']} has public, anonymous, or world-readable access enabled."


def _has_sensitive_customer_data(text: str) -> bool:
    return bool(_detected_sensitive_phrases(text))


def _sensitive_data_items(text: str) -> List[str]:
    return _detected_sensitive_phrases(text) or ["application data or customer records"]


def _storage_sensitive_data_items(text: str) -> List[str]:
    if not _has_storage(text):
        return []

    items = _detected_sensitive_phrases(text)
    if not items:
        return []

    storage_context_terms = [
        "s3",
        "bucket",
        "blob",
        "storage account",
        "storage container",
        "object storage",
        "customer export",
        "customer exports",
        "exports include",
        "some exports include",
    ]
    if _has_any(text, ["customer export", "customer exports", "exports include", "some exports include"]):
        return items

    strong_storage_context = [
        "bucket stores",
        "bucket contains",
        "s3 bucket stores",
        "s3 bucket contains",
        "object storage stores",
        "object storage contains",
        "blob stores",
        "blob contains",
        "storage container stores",
        "storage container contains",
        "storage account stores",
        "storage account contains",
    ]
    if not _has_any(text, strong_storage_context):
        return []

    return [item for item in items if _phrase_near_any(text, item.lower(), storage_context_terms)]


def _database_sensitive_data_items(text: str) -> List[str]:
    if not _has_database(text):
        return []

    items = _detected_sensitive_phrases(text)
    if not items:
        return []

    database_context_terms = [
        "rds",
        "database",
        "postgres",
        "postgresql",
        "mysql",
        "sql server",
        "aurora",
        "cosmos db",
        "dynamodb",
        "application stores",
    ]
    database_items = []
    for item in items:
        if item in {"logs", "backups", "exports"}:
            continue
        if _phrase_near_any(text, item.lower(), database_context_terms):
            database_items.append(item)
    return database_items


def _detected_sensitive_phrases(text: str) -> List[str]:
    phrase_patterns = [
        ("customer profile data", ["customer profile data", "customer profiles"]),
        ("billing metadata", ["billing metadata"]),
        ("email addresses", ["email addresses", "email address", "customer emails", "customer email"]),
        ("internal account IDs", ["internal account ids", "internal account id"]),
        ("account IDs", ["account ids", "account id"]),
        ("support history", ["support history"]),
        ("payment data", ["payment data", "payment details", "card data"]),
        ("PII", ["pii", "personally identifiable"]),
        ("credentials", ["credentials", "passwords", "tokens", "access keys"]),
        ("logs", ["logs", "log files"]),
        ("backups", ["backups", "backup files", "snapshots"]),
        ("exports", ["exports", "export files"]),
        ("customer data", ["customer data", "customer records"]),
        ("partner data", ["partner data"]),
    ]

    items = []
    for label, patterns in phrase_patterns:
        if _has_any(text, patterns) and label not in items:
            items.append(label)

    return _remove_broader_sensitive_terms(items)


def _remove_broader_sensitive_terms(items: List[str]) -> List[str]:
    cleaned = list(items)
    if "internal account IDs" in cleaned and "account IDs" in cleaned:
        cleaned.remove("account IDs")
    if any(item in cleaned for item in ["customer profile data", "email addresses", "billing metadata", "support history"]) and "customer data" in cleaned:
        cleaned.remove("customer data")
    if any(item in cleaned for item in ["customer profile data", "email addresses", "billing metadata", "support history", "payment data", "PII", "credentials"]) and "exports" in cleaned:
        cleaned.remove("exports")
    return cleaned


def _phrase_near_any(text: str, phrase: str, context_terms: List[str], window: int = 120) -> bool:
    phrase_index = text.find(phrase)
    if phrase_index == -1:
        return False

    for context in context_terms:
        context_index = text.find(context)
        while context_index != -1:
            if abs(context_index - phrase_index) <= window:
                return True
            context_index = text.find(context, context_index + 1)
    return False


def _sensitive_storage_title(text: str) -> str:
    storage_service = _provider_terms(text)["storage_service"]
    if _has_any(text, ["customer export", "customer exports", "email address", "email addresses", "internal account id", "internal account ids", "support history"]):
        return f"Sensitive customer exports are stored in {storage_service}"
    return f"Sensitive data is stored in {storage_service}"


def _format_list(items: List[str]) -> str:
    if len(items) <= 1:
        return items[0] if items else ""
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return f"{', '.join(items[:-1])}, and {items[-1]}"


def _has_shared_env_key(text: str) -> bool:
    key_terms = ["shared access key", "shared key", "access key", "storage key"]
    env_terms = [".env", "env file", "environment file", "local env"]
    return _has_any(text, key_terms) and _has_any(text, env_terms)


def _data_access_logging_missing(text: str) -> bool:
    if not _has_storage(text):
        return False

    read_terms = ["blob read", "blob reads", "storage read", "storage reads", "object read", "object reads", "bucket read", "bucket reads"]
    missing_terms = ["not configured", "not enabled", "disabled", "missing", "no logging", "without logging", "without alerting"]

    if _has_any(text, read_terms) and _has_any(text, missing_terms):
        return True
    if _has_any(text, ["logging and alerting", "logging", "alerting"]) and _has_any(text, missing_terms):
        return True
    return False


def _has_public_api(text: str) -> bool:
    return _has_any(
        text,
        [
            "public api",
            "public app service",
            "app service with a public api",
            "api gateway",
            "internet-facing api",
            "public endpoint",
        ],
    )


def _contractor_public_access_pattern(text: str) -> bool:
    return _has_any(text, ["contractor", "contractors"]) and _has_public_storage(text)


def _score_driver_sentence(finding_ids: set) -> str:
    if "CSA-002" in finding_ids and "CSA-013" in finding_ids and "CSA-014" in finding_ids:
        return "The score is driven by anonymous storage exposure, sensitive customer export contents, missing or weak telemetry, and a reusable shared key."
    if "CSA-002" in finding_ids and "CSA-013" in finding_ids:
        return "The score is driven by the combination of public storage and sensitive customer data."
    if "CSA-001" in finding_ids:
        return "The score is driven by direct internet reachability to the data tier."
    if "CSA-003" in finding_ids or "CSA-004" in finding_ids or "CSA-014" in finding_ids:
        return "The score is driven by credential and privilege paths that could widen compromise."
    return "The score is based on deterministic severity weights for the matched findings."


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
