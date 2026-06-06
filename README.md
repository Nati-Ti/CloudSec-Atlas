# CloudSec Atlas

CloudSec Atlas is a Streamlit MVP for the Microsoft Agents League Hackathon. It turns a plain-English cloud architecture description into a structured attack-path security review.

## Problem

Cloud teams often describe architecture in documents, tickets, and diagrams before the environment is fully deployed. Security review can be slow, inconsistent, or too dependent on expert availability. Teams need a fast way to reason about likely assets, risky exposure, attacker paths, blast radius, and remediation priorities.

## Solution

CloudSec Atlas provides an AI-inspired attack-path reasoning workflow without requiring a paid API key for the first MVP. The app uses deterministic Python rules to extract cloud assets, detect common security risks, simulate attacker paths, estimate blast radius, and produce a professional remediation report.

## Features

- Paste any cloud architecture description.
- Load one of three built-in demo scenarios.
- Run a local deterministic rule-based analysis.
- Review structured output sections:
  - Architecture Summary
  - Detected Assets
  - Security Findings
  - Attack Paths
  - Blast Radius
  - Prioritized Fix Roadmap
  - Verification Checklist
  - Safer Target Architecture
- Download the generated report as Markdown.
- Run locally with Streamlit and no authentication, database, or paid API key.

## How It Works

1. The user provides a cloud architecture description.
2. The analyzer normalizes the text and detects common asset categories such as public entry points, compute, databases, storage, IAM, network controls, secrets, and containers.
3. Rule checks identify risks such as public databases, public object storage, overprivileged IAM, secrets in code, broad inbound access, missing MFA, missing encryption, incomplete logging, and unclear backup posture.
4. CloudSec Atlas maps findings to likely attacker paths and estimates the blast radius.
5. The app generates a prioritized fix roadmap, verification checklist, safer target architecture, and downloadable Markdown report.

This MVP is intentionally deterministic so judges and demo users can see repeatable results without depending on external services.

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal, usually `http://localhost:8501`.

## Demo Scenarios

- `examples/startup_public_db.md`: AWS SaaS application with a publicly accessible RDS database and broad network exposure.
- `examples/insecure_storage.md`: Azure analytics workflow with public Blob Storage access and weak secret handling.
- `examples/overprivileged_iam.md`: AWS serverless workflow with AdministratorAccess, hardcoded credentials, and weak admin controls.

## Future Roadmap

- Add optional LLM-backed analysis for richer natural-language extraction.
- Support diagram upload or architecture-as-code parsing.
- Add cloud-provider-specific rule packs for AWS, Azure, and Google Cloud.
- Map findings to MITRE ATT&CK Cloud techniques and compliance controls.
- Generate executive and technical report variants.
- Add remediation validation against live cloud configuration exports.
- Support team workflows such as saved reports, comments, and review history.

## Notes

CloudSec Atlas is a hackathon MVP and should not be treated as a production cloud scanner. Use it to accelerate review conversations, identify likely risks, and create a clear remediation plan.
