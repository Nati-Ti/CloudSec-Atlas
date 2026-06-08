from html import escape
from pathlib import Path
from typing import Dict, List, Optional

import streamlit as st

from agent.analyzer import analyze_architecture, detect_provider, render_report_markdown
from agent.llm_enhancer import enhance_report_with_llm
from agent.terraform_scanner import detect_terraform_risks, generate_terraform_remediation_patch


BASE_DIR = Path(__file__).parent
EXAMPLES_DIR = BASE_DIR / "examples"

SAMPLE_SCENARIOS = {
    "AWS Startup Public Database": EXAMPLES_DIR / "aws_startup_public_database.md",
    "Azure Public Blob Storage": EXAMPLES_DIR / "azure_public_blob_storage.md",
    "AWS Overprivileged IAM Role": EXAMPLES_DIR / "aws_overprivileged_iam_role.md",
    "Generic Public Admin Dashboard": EXAMPLES_DIR / "generic_public_admin_dashboard.md",
    "Azure Key Vault Secret Exposure": EXAMPLES_DIR / "azure_key_vault_secret_exposure.md",
    "AWS Public S3 Data Lake": EXAMPLES_DIR / "aws_public_s3_data_lake.md",
    "Generic Flat Network No Segmentation": EXAMPLES_DIR / "generic_flat_network_no_segmentation.md",
    "Serverless API Missing Auth": EXAMPLES_DIR / "serverless_api_missing_auth.md",
}


def read_sample(path: Optional[Path]) -> str:
    if path is None:
        return ""
    return path.read_text(encoding="utf-8")


def page_styles() -> None:
    st.markdown(
        """
        <style>
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
        }
        .atlas-header {
            border-bottom: 1px solid #d7dde8;
            padding-bottom: 1rem;
            margin-bottom: 1.25rem;
        }
        .atlas-header h1 {
            margin: 0;
            font-size: 2rem;
            letter-spacing: 0;
        }
        .atlas-header p {
            margin: .25rem 0 0 0;
            color: #536173;
            font-size: 1rem;
        }
        .metric-card {
            border: 1px solid #d7dde8;
            border-radius: 8px;
            padding: 1rem;
            background: #ffffff;
            min-height: 112px;
        }
        .metric-label {
            color: #687386;
            font-size: .78rem;
            text-transform: uppercase;
            letter-spacing: .04em;
            margin-bottom: .35rem;
        }
        .metric-value {
            color: #111827;
            font-size: 1.35rem;
            font-weight: 700;
            line-height: 1.25;
        }
        .metric-help {
            color: #65758b;
            font-size: .84rem;
            margin-top: .35rem;
        }
        .timeline-step {
            border-left: 3px solid #2563eb;
            padding: .1rem 0 .95rem 1rem;
            margin-left: .45rem;
        }
        .timeline-index {
            color: #1d4ed8;
            font-weight: 700;
            font-size: .82rem;
            margin-bottom: .15rem;
        }
        .roadmap-card {
            border: 1px solid #d7dde8;
            border-radius: 8px;
            padding: 1rem;
            background: #ffffff;
            min-height: 190px;
        }
        .priority {
            display: inline-block;
            font-weight: 700;
            color: #111827;
            border: 1px solid #cbd5e1;
            border-radius: 999px;
            padding: .15rem .55rem;
            margin-bottom: .55rem;
            font-size: .8rem;
        }
        .roadmap-action {
            font-weight: 650;
            color: #111827;
            margin-bottom: .55rem;
        }
        .roadmap-outcome {
            color: #536173;
            font-size: .9rem;
        }
        .iac-risk {
            border: 1px solid #f2c48d;
            border-radius: 8px;
            padding: .85rem;
            background: #fffaf3;
            margin-bottom: .65rem;
        }
        .muted {
            color: #64748b;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header() -> None:
    st.markdown(
        """
        <div class="atlas-header">
            <h1>CloudSec Atlas</h1>
            <p>Attack-Path Reasoning Agent for Cloud Security</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_section_header(title: str) -> None:
    st.markdown(f"### {title}")


def metric_card(label: str, value: str, help_text: str = "") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{escape(label)}</div>
            <div class="metric-value">{escape(value)}</div>
            <div class="metric-help">{escape(help_text)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def run_analysis(architecture_text: str, source_label: str, use_llm: bool) -> None:
    report = analyze_architecture(architecture_text)
    markdown_report = render_report_markdown(report, architecture_text)
    llm_message = ""

    if use_llm:
        with st.spinner("Enhancing report with Azure AI Foundry..."):
            markdown_report, llm_message = enhance_report_with_llm(markdown_report, architecture_text)

    st.session_state["analysis"] = {
        "source_label": source_label,
        "architecture_text": architecture_text,
        "provider": detect_provider(architecture_text),
        "report": report,
        "markdown_report": markdown_report,
        "llm_message": llm_message,
    }


def render_dashboard_cards(provider: str, report) -> None:
    top_attack_path = report.attack_paths[0].name if report.attack_paths else "No path generated"
    cols = st.columns(5)
    with cols[0]:
        metric_card("Provider", provider, "Detected from architecture text")
    with cols[1]:
        metric_card("Overall Risk", report.risk_label, "Rule-based severity model")
    with cols[2]:
        metric_card("Score", f"{report.risk_score}/100", "Explainable score drivers")
    with cols[3]:
        metric_card("Findings", str(len(report.findings)), "Prioritized security issues")
    with cols[4]:
        metric_card("Top Attack Path", top_attack_path, "Primary chain to break")


def render_score_drivers(report) -> None:
    render_section_header("Score Drivers")
    for driver in report.score_drivers:
        st.markdown(f"- {driver}")


def render_findings(report) -> None:
    render_section_header("Security Findings")
    for finding in report.findings:
        with st.expander(f"{finding.severity}: {finding.title}", expanded=True):
            st.markdown(f"**Affected assets:** {', '.join(finding.affected_assets)}")
            st.markdown(f"**Evidence:** {finding.evidence}")
            st.markdown(f"**Why this matters:** {finding.why_this_matters}")
            st.markdown(f"**Impact:** {finding.impact}")
            st.markdown(f"**Recommended fix:** {finding.recommendation}")


def render_attack_timeline(report) -> None:
    render_section_header("Attack Paths")
    for path in report.attack_paths:
        with st.expander(path.name, expanded=True):
            st.markdown(f"**Difficulty:** {path.difficulty}")
            st.markdown(f"**Likely impact:** {path.impact}")
            st.markdown("**Timeline:**")
            for index, step in enumerate(path.steps, start=1):
                st.markdown(
                    f"""
                    <div class="timeline-step">
                        <div class="timeline-index">Step {index}</div>
                        <div>{escape(step)}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            st.markdown(f"**Broken by:** {path.blocked_by}")


def render_roadmap(report) -> None:
    render_section_header("Prioritized Fix Roadmap")
    columns = st.columns(4)
    for index, item in enumerate(report.fix_roadmap):
        with columns[index % 4]:
            st.markdown(
                f"""
                <div class="roadmap-card">
                    <div class="priority">{escape(item.priority)}</div>
                    <div class="roadmap-action">{escape(item.action)}</div>
                    <div class="roadmap-outcome">{escape(item.expected_outcome)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_report(markdown_report: str, provider: str, report) -> None:
    render_dashboard_cards(provider, report)

    render_section_header("Architecture Summary")
    st.write(report.architecture_summary)

    render_score_drivers(report)

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

    render_findings(report)
    render_attack_timeline(report)

    render_section_header("Blast Radius")
    for item in report.blast_radius:
        st.markdown(f"- {item}")

    render_roadmap(report)

    render_section_header("Verification Checklist")
    for index, item in enumerate(report.verification_checklist):
        st.checkbox(item, value=False, key=f"verify_{index}_{item}")

    render_section_header("Safer Target Architecture")
    for item in report.safer_target_architecture:
        st.markdown(f"- {item}")

    st.download_button(
        "Download Markdown Report",
        data=markdown_report,
        file_name="cloudsec-atlas-report.md",
        mime="text/markdown",
    )


def render_sample_tab(use_llm: bool) -> None:
    selected = st.selectbox("Choose a scenario", options=list(SAMPLE_SCENARIOS.keys()))
    sample_text = read_sample(SAMPLE_SCENARIOS[selected])
    st.text_area("Scenario architecture description", value=sample_text, height=280, key=f"sample_{selected}")

    if st.button("Analyze Sample Scenario", type="primary"):
        run_analysis(sample_text, selected, use_llm)


def render_paste_tab(use_llm: bool) -> None:
    architecture_text = st.text_area(
        "Paste cloud architecture description",
        height=320,
        placeholder=(
            "Example: An AWS web app uses an internet-facing ALB, EC2 app servers, "
            "an RDS PostgreSQL database, S3 storage, IAM roles, and CloudWatch logs..."
        ),
        key="custom_architecture_text",
    )

    if st.button("Analyze Pasted Architecture", type="primary"):
        if not architecture_text.strip():
            st.warning("Paste an architecture description first.")
            return
        run_analysis(architecture_text, "Custom architecture", use_llm)


def render_diagram_tab() -> None:
    st.info("Coming soon: Azure AI Foundry vision extraction.")
    st.write(
        "The next version will accept architecture diagrams, extract cloud services and trust boundaries, "
        "and feed the normalized description into the same attack-path analyzer."
    )


def read_uploaded_file(uploaded_file) -> str:
    return uploaded_file.getvalue().decode("utf-8", errors="replace")


def render_iac_risks(risks: List[Dict[str, str]]) -> None:
    if not risks:
        st.success("No obvious risky Terraform patterns detected by the scanner.")
        return

    st.markdown("#### Detected IaC Risks")
    for risk in risks:
        st.markdown(
            f"""
            <div class="iac-risk">
                <strong>{escape(risk["severity"])}: {escape(risk["title"])}</strong><br />
                <span class="muted">Evidence:</span> {escape(risk["evidence"])}<br />
                <span class="muted">Recommendation:</span> {escape(risk["recommendation"])}
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_terraform_tab() -> None:
    uploaded_files = st.file_uploader(
        "Upload Terraform .tf files",
        type=["tf"],
        accept_multiple_files=True,
    )

    if not uploaded_files:
        st.info("Upload one or more Terraform files to run a lightweight risk scan.")
        return

    combined_content = []
    for uploaded_file in uploaded_files:
        content = read_uploaded_file(uploaded_file)
        combined_content.append(f"# {uploaded_file.name}\n{content}")
        with st.expander(f"View {uploaded_file.name}", expanded=False):
            st.code(content, language="hcl")

    terraform_text = "\n\n".join(combined_content)
    risks = detect_terraform_risks(terraform_text)
    render_iac_risks(risks)

    if st.session_state.get("terraform_source_text") != terraform_text:
        st.session_state["terraform_source_text"] = terraform_text
        st.session_state.pop("terraform_remediation_patch", None)

    if st.button("Generate Remediation Patch"):
        st.session_state["terraform_remediation_patch"] = generate_terraform_remediation_patch(terraform_text)

    remediation_patch = st.session_state.get("terraform_remediation_patch")
    if remediation_patch:
        st.markdown("#### Suggested Remediation Patch")
        st.warning("This patch is advisory. Review and test before applying with Terraform.")
        st.code(remediation_patch, language="hcl")
        st.download_button(
            "Download Suggested Patch",
            data=remediation_patch,
            file_name="cloudsec-atlas-remediation.tf",
            mime="text/plain",
        )


def render_analysis_output() -> None:
    analysis = st.session_state.get("analysis")
    if not analysis:
        st.info("Choose a sample or paste an architecture, then run analysis.")
        return

    st.divider()
    st.caption(f"Current report source: {analysis['source_label']}")
    if analysis["llm_message"]:
        message = analysis["llm_message"]
        if message.startswith("LLM enhancement applied"):
            st.success(message)
        elif "failed" in message or "skipped" in message:
            st.warning(message)
        else:
            st.info(message)

    render_report(
        markdown_report=analysis["markdown_report"],
        provider=analysis["provider"],
        report=analysis["report"],
    )


def main() -> None:
    st.set_page_config(
        page_title="CloudSec Atlas",
        page_icon="CSA",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    page_styles()
    render_header()

    with st.sidebar:
        st.header("Analysis Mode")
        st.write("Deterministic rules run offline and remain the source of truth.")
        use_llm = st.toggle("Enhance report with Azure AI Foundry", value=False)
        st.divider()
        st.markdown("**Demo flow**")
        st.write("Use the AWS public database scenario for the strongest end-to-end attack-path narrative.")

    sample_tab, paste_tab, diagram_tab, terraform_tab = st.tabs(
        ["Sample Scenario", "Paste Architecture", "Upload Diagram", "Upload Terraform"]
    )

    with sample_tab:
        render_sample_tab(use_llm)
    with paste_tab:
        render_paste_tab(use_llm)
    with diagram_tab:
        render_diagram_tab()
    with terraform_tab:
        render_terraform_tab()

    render_analysis_output()


if __name__ == "__main__":
    main()
