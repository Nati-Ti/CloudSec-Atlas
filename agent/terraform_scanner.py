from __future__ import annotations

import re
from typing import Dict, List


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

    wildcard_patterns = [
        r"actions\s*=\s*\[[^\]]*[\"']\*[\"']",
        r"resources\s*=\s*\[[^\]]*[\"']\*[\"']",
        r"action\s*=\s*[\"']\*[\"']",
        r"resource\s*=\s*[\"']\*[\"']",
        r"[\"']\*:\*[\"']",
    ]
    if any(re.search(pattern, lowered, flags=re.DOTALL) for pattern in wildcard_patterns):
        risks.append(
            {
                "severity": "High",
                "title": "Wildcard IAM permission detected",
                "evidence": "Detected wildcard IAM action or resource usage.",
                "recommendation": "Scope IAM permissions to required actions and resources only.",
            }
        )

    return risks
