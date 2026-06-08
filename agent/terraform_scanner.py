from __future__ import annotations

import re
from typing import Dict, List


def generate_terraform_remediation_patch(terraform_text: str) -> str:
    lowered = terraform_text.lower()
    patch_sections = [
        "# CloudSec Atlas Suggested Terraform Remediation Patch",
        "# This file is advisory. Review resource names, dependencies, and environment-specific values before use.",
        "",
    ]

    if re.search(r"publicly_accessible\s*=\s*true", lowered):
        patch_sections.extend(
            [
                "# Disable public database accessibility.",
                "# Apply inside the affected aws_db_instance or compatible database resource.",
                "publicly_accessible = false",
                "",
            ]
        )

    has_public_cidr = bool(re.search(r"cidr_blocks\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']\s*\]", lowered))
    has_postgres_port = bool(re.search(r"from_port\s*=\s*5432", lowered))
    if has_public_cidr and has_postgres_port:
        patch_sections.extend(
            [
                "# Restrict PostgreSQL ingress to the application tier instead of the public internet.",
                "# Replace aws_security_group.db_sg.id with the database security group ID.",
                "# Replace aws_security_group.app_sg.id with the application security group ID.",
                "# Remove cidr_blocks = [\"0.0.0.0/0\"] from the old rule.",
                "resource \"aws_security_group_rule\" \"postgres_from_app\" {",
                "  type                     = \"ingress\"",
                "  security_group_id        = aws_security_group.db_sg.id",
                "  from_port                = 5432",
                "  to_port                  = 5432",
                "  protocol                 = \"tcp\"",
                "  source_security_group_id = aws_security_group.app_sg.id",
                "  description              = \"Allow PostgreSQL only from the application security group\"",
                "}",
                "",
            ]
        )

    admin_ports = []
    if has_public_cidr and re.search(r"from_port\s*=\s*22", lowered):
        admin_ports.append(("SSH", 22))
    if has_public_cidr and re.search(r"from_port\s*=\s*3389", lowered):
        admin_ports.append(("RDP", 3389))
    if admin_ports:
        patch_sections.extend(_admin_cidr_variable_patch())
        for protocol, port in admin_ports:
            patch_sections.extend(_admin_access_patch(protocol, port))

    if _has_wildcard_iam(terraform_text):
        patch_sections.extend(
            [
                "# Replace wildcard IAM permissions with least-privilege scoped actions and resources.",
                "# TODO: Replace these examples with only the actions and ARNs required by the workload.",
                "actions = [",
                "  # \"service:RequiredAction\",",
                "]",
                "",
                "resources = [",
                "  # \"arn:aws:service:region:account-id:resource/resource-id\",",
                "]",
                "",
            ]
        )

    if len(patch_sections) == 3:
        patch_sections.extend(
            [
                "# No supported high-risk Terraform patterns were detected.",
                "# Re-run after uploading Terraform that includes database, network, or IAM resources.",
                "",
            ]
        )

    return "\n".join(patch_sections).strip() + "\n"


def detect_terraform_risks(terraform_text: str) -> List[Dict[str, str]]:
    lowered = terraform_text.lower()
    risks: List[Dict[str, str]] = []

    if re.search(r"publicly_accessible\s*=\s*true", lowered):
        risks.append(
            {
                "severity": "High",
                "title": "Public database accessibility is enabled",
                "evidence": "Detected `publicly_accessible = true`.",
                "recommendation": "Disable public accessibility and place the database in private subnets.",
            }
        )

    if re.search(r"cidr_blocks\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']\s*\]", lowered):
        risks.append(
            {
                "severity": "High",
                "title": "Security rule allows traffic from 0.0.0.0/0",
                "evidence": "Detected `cidr_blocks = [\"0.0.0.0/0\"]`.",
                "recommendation": "Restrict ingress to approved application security groups, private subnets, or trusted IP ranges.",
            }
        )

    if re.search(r"from_port\s*=\s*5432", lowered):
        risks.append(
            {
                "severity": "High",
                "title": "PostgreSQL ingress rule detected",
                "evidence": "Detected `from_port = 5432`.",
                "recommendation": "Confirm PostgreSQL is reachable only from the application tier.",
            }
        )

    if re.search(r"from_port\s*=\s*22", lowered):
        risks.append(
            {
                "severity": "High",
                "title": "SSH ingress rule detected",
                "evidence": "Detected `from_port = 22`.",
                "recommendation": "Remove public SSH and use bastion, SSM, or just-in-time access.",
            }
        )

    if re.search(r"from_port\s*=\s*3389", lowered):
        risks.append(
            {
                "severity": "High",
                "title": "RDP ingress rule detected",
                "evidence": "Detected `from_port = 3389`.",
                "recommendation": "Remove public RDP and use a controlled administrative access pattern.",
            }
        )

    if _has_wildcard_iam(terraform_text):
        risks.append(
            {
                "severity": "High",
                "title": "Wildcard IAM permission detected",
                "evidence": "Detected wildcard IAM action or resource usage.",
                "recommendation": "Scope IAM permissions to required actions and resources only.",
            }
        )

    return risks


def _admin_cidr_variable_patch() -> List[str]:
    return [
        "variable \"trusted_admin_cidr\" {",
        "  description = \"Temporary trusted admin CIDR. Prefer bastion/JIT access instead.\"",
        "  type        = string",
        "  # TODO: Set to an approved admin network, for example \"203.0.113.10/32\".",
        "}",
        "",
    ]


def _admin_access_patch(protocol: str, port: int) -> List[str]:
    return [
        f"# Restrict public {protocol} access on port {port}.",
        "# Prefer bastion, AWS Systems Manager Session Manager, VPN, or just-in-time access.",
        "# If direct access is temporarily required, scope it to a trusted admin CIDR.",
        "# Replace the public CIDR on the affected management ingress rule.",
        "cidr_blocks = [var.trusted_admin_cidr]",
        "",
    ]


def _has_wildcard_iam(terraform_text: str) -> bool:
    lowered = terraform_text.lower()
    wildcard_patterns = [
        r"actions\s*=\s*\[[^\]]*[\"']\*[\"']",
        r"resources\s*=\s*\[[^\]]*[\"']\*[\"']",
        r"action\s*=\s*[\"']\*[\"']",
        r"resource\s*=\s*[\"']\*[\"']",
        r"[\"']\*:\*[\"']",
    ]
    return any(re.search(pattern, lowered, flags=re.DOTALL) for pattern in wildcard_patterns)
