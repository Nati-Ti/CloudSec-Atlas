from pathlib import Path
from typing import Optional

import streamlit as st

from agent.analyzer import analyze_architecture, render_report_markdown


BASE_DIR = Path(__file__).parent
EXAMPLES_DIR = BASE_DIR / "examples"

SAMPLE_SCENARIOS = {
    "Custom architecture": None,
    "Startup public database": EXAMPLES_DIR / "startup_public_db.md",
    "Insecure storage": EXAMPLES_DIR / "insecure_storage.md",
    "Overprivileged IAM": EXAMPLES_DIR / "overprivileged_iam.md",
}


def read_sample(path: Optional[Path]) -> str:
    if path is None:
        return ""
    return path.read_text(encoding="utf-8")


def render_section_header(title: str) -> None:
    st.markdown(f"### {title}")


def render_report(report, markdown_report: str) -> None:
    score_col, label_col, count_col = st.columns(3)
    score_col.metric("Risk Score", f"{report.risk_score}/100")
    label_col.metric("Risk Level", report.risk_label)
    count_col.metric("Findings", len(report.findings))

    render_section_header("Score Drivers")
    for driver in report.score_drivers:
        st.markdown(f"- {driver}")

    render_section_header("Architecture Summary")
    st.write(report.architecture_summary)

    render_section_header("Detected Assets")
    st.table(
        [
            {
                "Asset": asset.name,
                "Type": asset.type,
                "Exposure": asset.exposure,
                "Notes": asset.notes,
            }
            for asset in report.assets
        ]
    )

    render_section_header("Security Findings")
    for finding in report.findings:
        with st.expander(f"{finding.severity}: {finding.title}", expanded=True):
            st.markdown(f"**Affected assets:** {', '.join(finding.affected_assets)}")
            st.markdown(f"**Evidence:** {finding.evidence}")
            st.markdown(f"**Why this matters:** {finding.why_this_matters}")
            st.markdown(f"**Impact:** {finding.impact}")
            st.markdown(f"**Recommended fix:** {finding.recommendation}")

    render_section_header("Attack Paths")
    for path in report.attack_paths:
        with st.expander(path.name, expanded=True):
            st.markdown(f"**Difficulty:** {path.difficulty}")
            st.markdown(f"**Likely impact:** {path.impact}")
            st.markdown("**Path steps:**")
            for step in path.steps:
                st.markdown(f"- {step}")
            st.markdown(f"**Broken by:** {path.blocked_by}")

    render_section_header("Blast Radius")
    for item in report.blast_radius:
        st.markdown(f"- {item}")

    render_section_header("Prioritized Fix Roadmap")
    st.table(
        [
            {
                "Priority": item.priority,
                "Action": item.action,
                "Expected Outcome": item.expected_outcome,
            }
            for item in report.fix_roadmap
        ]
    )

    render_section_header("Verification Checklist")
    for item in report.verification_checklist:
        st.checkbox(item, value=False)

    render_section_header("Safer Target Architecture")
    for item in report.safer_target_architecture:
        st.markdown(f"- {item}")

    st.download_button(
        "Download Markdown Report",
        data=markdown_report,
        file_name="cloudsec-atlas-report.md",
        mime="text/markdown",
    )


def main() -> None:
    st.set_page_config(
        page_title="CloudSec Atlas",
        page_icon="CSA",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.title("CloudSec Atlas")
    st.caption(
        "AI-inspired attack-path reasoning for cloud security, powered by a deterministic MVP rules engine."
    )

    with st.sidebar:
        st.header("Scenario")
        selected_scenario = st.selectbox(
            "Load sample scenario",
            options=list(SAMPLE_SCENARIOS.keys()),
        )
        st.divider()
        st.markdown("**MVP mode**")
        st.write("Rule-based analysis. No paid API key required.")
        st.markdown("**Best inputs**")
        st.write("Include services, network exposure, identities, storage, data sensitivity, and logging posture.")

    sample_text = read_sample(SAMPLE_SCENARIOS[selected_scenario])
    architecture_text = st.text_area(
        "Cloud architecture description",
        value=sample_text,
        height=300,
        key=f"architecture_input_{selected_scenario}",
        placeholder=(
            "Example: A public web app uses an internet-facing load balancer, "
            "two VMs in a private subnet, an RDS PostgreSQL database, and an IAM role..."
        ),
    )

    analyze_clicked = st.button("Analyze Architecture", type="primary")

    if analyze_clicked:
        if not architecture_text.strip():
            st.warning("Paste an architecture description or choose a sample scenario first.")
            return

        report = analyze_architecture(architecture_text)
        markdown_report = render_report_markdown(report, architecture_text)
        render_report(report, markdown_report)
    else:
        st.info("Paste an architecture description or choose a sample, then run the analysis.")


if __name__ == "__main__":
    main()
