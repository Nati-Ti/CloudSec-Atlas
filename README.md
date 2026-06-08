# CloudSec Atlas

CloudSec Atlas is a Streamlit MVP for the Microsoft Agents League Hackathon. It turns a plain-English cloud architecture description into a structured attack-path security review with provider-aware findings, scoring, remediation priorities, and a downloadable Markdown report.

## Problem

Cloud teams often describe architecture in documents, tickets, diagrams, and infrastructure-as-code before the environment is fully deployed. Security review can be slow, inconsistent, or too dependent on expert availability. Teams need a fast way to reason about likely assets, risky exposure, attacker paths, blast radius, and remediation priorities.

## Solution

CloudSec Atlas provides an AI-inspired attack-path reasoning workflow without requiring a paid API key for the MVP. The app uses deterministic Python rules to extract cloud assets, detect common security risks, simulate attacker paths, estimate blast radius, and produce a professional remediation report.

The codebase also includes an optional Azure AI Foundry / Azure OpenAI enhancement layer. The deterministic rule engine remains the source of truth; the LLM only improves Markdown report wording and presentation. If Azure OpenAI environment variables are not configured, the app keeps running in offline rules mode.

## Features

- Professional Streamlit security dashboard with provider, risk, score, findings count, and top attack path cards.
- Four input tabs: Sample Scenario, Paste Architecture, Upload Diagram, and Upload Terraform.
- Deterministic provider-aware analysis for AWS, Azure, and generic cloud descriptions.
- Expandable security findings with evidence, impact, recommended fix, and a "Why this matters" explanation.
- Step-by-step attack-path timelines.
- P0/P1/P2/P3 remediation roadmap cards.
- Verification checklist and safer target architecture guidance.
- Markdown report export.
- Optional Azure AI Foundry / Azure OpenAI Markdown report enhancement with metadata guardrails.
- Terraform upload with simple risk detection and advisory remediation patch generation for public ingress, public databases, management ports, and wildcard IAM permissions.

## How It Works

1. The user loads a sample scenario, pastes an architecture description, or uploads Terraform.
2. The analyzer normalizes the text and detects cloud provider context, assets, sensitive data phrases, exposure patterns, identity risks, logging gaps, and recovery gaps.
3. Rule checks generate findings with explainable score drivers.
4. CloudSec Atlas maps findings into likely attacker paths and estimates the blast radius.
5. The app generates a prioritized fix roadmap, verification checklist, safer target architecture, and downloadable Markdown report.
6. If the optional LLM enhancement toggle is enabled, CloudSec Atlas runs the deterministic analyzer first, then asks Azure OpenAI to improve the Markdown report. If settings are missing or the enhanced draft changes protected metadata, the original rule-based report is kept.

This MVP is intentionally deterministic so judges and demo users can see repeatable results without depending on external services.

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal, usually `http://localhost:8501`.

## Optional Environment

Copy `.env.example` if you want to prepare local settings for the optional Azure OpenAI report enhancement layer:

```bash
cp .env.example .env
```

The current MVP does not require these values for offline rule-based analysis:

```text
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_API_KEY=
AZURE_OPENAI_DEPLOYMENT=
AZURE_OPENAI_API_VERSION=2024-10-21
```

## Demo Scenarios

- `examples/aws_startup_public_database.md`: AWS SaaS app with internet-facing ALB, EC2, public RDS PostgreSQL, customer profile data, and billing metadata.
- `examples/azure_public_blob_storage.md`: Azure App Service workflow with public Blob Storage, customer exports, shared key use, and missing blob read alerts.
- `examples/aws_overprivileged_iam_role.md`: AWS serverless workflow with broad IAM permissions and sensitive operational data.
- `examples/generic_public_admin_dashboard.md`: Public admin dashboard without strong identity and management controls.
- `examples/azure_key_vault_secret_exposure.md`: Azure workload with weak Key Vault and secret handling patterns.
- `examples/aws_public_s3_data_lake.md`: Public S3 data lake exposure with sensitive analytics and object access concerns.
- `examples/generic_flat_network_no_segmentation.md`: Flat cloud network where app, data, and admin workloads share broad reachability.
- `examples/serverless_api_missing_auth.md`: Serverless API flow with weak authentication and sensitive backend access.

## Terraform Remediation Assistant

The Upload Terraform tab accepts `.tf` files, displays the file content, and flags obvious risky patterns such as:

- `publicly_accessible = true`
- `cidr_blocks = ["0.0.0.0/0"]`
- `from_port = 5432`
- `from_port = 22`
- `from_port = 3389`
- Wildcard IAM actions or resources such as `"*"`

The "Generate Remediation Patch" button creates an advisory Terraform snippet that suggests safer settings such as private database access, a PostgreSQL `aws_security_group_rule` scoped to the application Security Group, trusted-admin CIDRs for management ports, and TODO-marked least-privilege IAM replacements. CloudSec Atlas never applies Terraform automatically and does not require cloud credentials.

## Future Roadmap

- Expand Azure AI Foundry / Azure OpenAI enhancement with richer analyst-style report refinement.
- Add diagram upload with vision-based architecture extraction.
- Add deeper Terraform parsing and generated remediation patches with human review.
- Add provider-specific rule packs for AWS, Azure, and Google Cloud.
- Map findings to MITRE ATT&CK Cloud techniques and compliance controls.
- Generate executive and technical report variants.
- Add remediation validation against live cloud configuration exports.
- Support team workflows such as saved reports, comments, and review history.

## Notes

CloudSec Atlas is a hackathon MVP and should not be treated as a production cloud scanner. Use it to accelerate review conversations, identify likely risks, and create a clear remediation plan.
