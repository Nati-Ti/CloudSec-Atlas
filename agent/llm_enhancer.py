from __future__ import annotations

import os
from typing import Tuple


REQUIRED_AZURE_OPENAI_ENV = [
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_DEPLOYMENT",
    "AZURE_OPENAI_API_VERSION",
]


def enhance_report_with_llm(report_markdown: str, architecture_text: str) -> Tuple[str, str]:
    missing = [name for name in REQUIRED_AZURE_OPENAI_ENV if not os.getenv(name)]
    if missing:
        return (
            report_markdown,
            "LLM enhancement is disabled because Azure OpenAI environment variables are not configured.",
        )

    return (
        report_markdown,
        "Azure OpenAI configuration detected. LLM enhancement is a placeholder in this MVP, so no external API call was made.",
    )
