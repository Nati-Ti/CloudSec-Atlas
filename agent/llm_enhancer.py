from __future__ import annotations

import os
import re


REQUIRED_AZURE_OPENAI_ENV = [
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_DEPLOYMENT",
    "AZURE_OPENAI_API_VERSION",
]

SYSTEM_PROMPT = (
    "You are CloudSec Atlas, a cloud security report enhancement agent. Improve the clarity, "
    "structure, and executive readability of the provided report. Do not invent new findings, "
    "assets, attack paths, services, or evidence. Preserve all severities, scores, findings, "
    "and remediation steps. You may improve wording, add concise explanations, and make the "
    "report more professional."
)


def enhance_report_with_llm(report_markdown: str, architecture_text: str) -> tuple[str, str]:
    _load_dotenv_if_available()

    missing = [name for name in REQUIRED_AZURE_OPENAI_ENV if not os.getenv(name)]
    if missing:
        return report_markdown, "LLM enhancement disabled: missing Azure OpenAI environment variables."

    try:
        from openai import AzureOpenAI
    except ImportError:
        return (
            report_markdown,
            "LLM enhancement failed: OpenAI Python package is not installed. Run pip install -r requirements.txt.",
        )

    client = AzureOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        api_version=os.environ["AZURE_OPENAI_API_VERSION"],
    )

    user_prompt = (
        "Source architecture description:\n"
        "```text\n"
        f"{architecture_text.strip()}\n"
        "```\n\n"
        "Rule-based report markdown:\n"
        "```markdown\n"
        f"{report_markdown.strip()}\n"
        "```\n\n"
        "Protected report metadata must remain unchanged:\n"
        f"{_protected_metadata_summary(report_markdown)}\n\n"
        "Return the enhanced markdown report only."
    )

    try:
        response = client.chat.completions.create(
            model=os.environ["AZURE_OPENAI_DEPLOYMENT"],
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
    except Exception:
        return (
            report_markdown,
            "LLM enhancement failed: using the original rule-based report. Check Azure OpenAI configuration and network access.",
        )

    enhanced_markdown = (response.choices[0].message.content or "").strip()
    if not enhanced_markdown:
        return report_markdown, "LLM enhancement failed: Azure OpenAI returned an empty response."

    is_valid, reason = _protected_metadata_preserved(report_markdown, enhanced_markdown)
    if not is_valid:
        return report_markdown, f"LLM enhancement skipped: {reason} The rule-based report was kept."

    return (
        enhanced_markdown,
        "LLM enhancement applied with Azure AI Foundry / Azure OpenAI. Rule-based findings, scores, and remediation steps were preserved.",
    )


def _load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()


def _protected_metadata_preserved(original_markdown: str, enhanced_markdown: str) -> tuple[bool, str]:
    original_risk = _overall_risk(original_markdown)
    enhanced_risk = _overall_risk(enhanced_markdown)
    if original_risk and original_risk != enhanced_risk:
        return False, "the enhanced draft changed or removed the overall risk score."

    original_scores = set(re.findall(r"\b\d{1,3}/100\b", original_markdown))
    enhanced_scores = set(re.findall(r"\b\d{1,3}/100\b", enhanced_markdown))
    unexpected_scores = enhanced_scores - original_scores
    if unexpected_scores:
        return False, "the enhanced draft introduced a different numerical score."

    original_ids = set(re.findall(r"`(CSA-\d+)`", original_markdown))
    enhanced_ids = set(re.findall(r"`(CSA-\d+)`", enhanced_markdown))
    if original_ids != enhanced_ids:
        return False, "the enhanced draft changed finding IDs."

    original_severities = _finding_severity_by_id(original_markdown)
    enhanced_severities = _finding_severity_by_id(enhanced_markdown)
    if original_severities != enhanced_severities:
        return False, "the enhanced draft changed one or more severity labels."

    return True, ""


def _overall_risk(markdown: str) -> tuple[str, str] | None:
    match = re.search(r"Overall risk:\s*\*\*(Critical|High|Medium|Low)\*\*\s*\((\d{1,3}/100)\)", markdown)
    if not match:
        return None
    return match.group(1), match.group(2)


def _protected_metadata_summary(markdown: str) -> str:
    risk = _overall_risk(markdown)
    severity_by_id = _finding_severity_by_id(markdown)
    lines = []
    if risk:
        lines.append(f"- Overall risk: {risk[0]} ({risk[1]})")
    for finding_id, severity in sorted(severity_by_id.items()):
        lines.append(f"- {finding_id}: {severity}")
    return "\n".join(lines)


def _finding_severity_by_id(markdown: str) -> dict[str, str]:
    section_pattern = re.compile(
        r"^###\s+(Critical|High|Medium|Low):.*?(?=^###\s+(?:Critical|High|Medium|Low):|\Z)",
        flags=re.MULTILINE | re.DOTALL,
    )
    severity_by_id: dict[str, str] = {}
    for match in section_pattern.finditer(markdown):
        section = match.group(0)
        severity = match.group(1)
        for finding_id in re.findall(r"`(CSA-\d+)`", section):
            severity_by_id[finding_id] = severity
    return severity_by_id
