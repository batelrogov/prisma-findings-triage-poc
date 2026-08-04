**Open-Source Reference Architecture & Disclaimer**

This repository contains an independent, open-source proof of concept developed
for educational and architectural purposes. It is not affiliated with or
endorsed by any employer or product vendor.

# Prisma Findings Triage POC

A focused Phase 1 proof of concept for finding repeated pain points in large
Prisma Cloud reports. It classifies report rows as:

- **Recurring** — a repeated policy/resource/remediation pattern worth assessing
  as an automation or preventive-control candidate.
- **Unique** — an isolated or context-dependent finding that needs individual review.
- **Needs More Information** — a finding that cannot be routed safely without
  additional policy, resource, ownership, or management context.

The POC helps identify where automation may provide value. It does not remediate
findings, change AWS resources, run scripts, create Terraform, or replace Prisma.

## Why this exists

Large periodic Prisma reports can contain thousands of rows. Before remediation
starts, a reviewer must identify repeated patterns, prioritize them, and separate
potential shared fixes from findings that require business context. This project
turns that first-pass analysis into a consistent, reviewable workflow.

## Components

- `prisma_triage_agent.py` — deterministic reference implementation for CSV/XLSX.
- `COPILOT_AGENT_INSTRUCTIONS.md` — guardrails and expected output for a Microsoft
  Copilot agent that reviews the report.
- `config.yaml` — recurring threshold, column aliases, worksheet, and output paths.

## Installation

Python 3.9 or newer is required.

```bash
python -m pip install -r requirements.txt
```

## Usage

```bash
python prisma_triage_agent.py path/to/prisma-findings.csv
```

CSV and XLSX input are supported. The default outputs are:

- `triage_report.md` — prioritized, human-readable pattern summary.
- `categorized_findings.csv` — original normalized findings plus category and route.

Column names vary between Prisma exports. Update `column_aliases` in `config.yaml`
when the report uses different headers.

## Classification approach

A complete finding needs a policy, resource type, and resource identifier. Complete
findings are grouped by policy, resource type, and remediation text. A group that
meets `recurring_min_count` is marked `Recurring`; smaller groups are `Unique`.
Incomplete findings are marked `Needs More Information` rather than guessed.

Severity and group size determine report ordering. They do not authorize action.

## Suggested routes

- A repeated pattern may be a Terraform template candidate only after the existing
  code and Terraform state confirm ownership.
- A reported unmanaged pattern may be a script-assisted or import candidate, but
  still requires human review, scope selection, dry run, impact review, rollback,
  and approval.
- Unique findings remain with a resource owner for contextual review.
- Patterns caused by the provisioning process may justify a preventive control.

## Safety boundaries

- The tool performs classification only.
- Absence from a report field is not proof that a resource was created manually.
- Terraform ownership must be verified against both code and state.
- All suggested routes are candidates, not approved remediation.
- Resource ownership, business impact, dependencies, rollback, and approval must
  be validated before any change.

## Roadmap

1. **Current:** report ingestion, normalization, classification, and prioritization.
2. **Ownership enrichment:** connect findings to approved code/state and owner data.
3. **Proposal generation:** prepare review-only remediation proposals.
4. **Read-only AWS MCP enrichment:** retrieve current resource context without changes.
5. **Governed lifecycle:** route approved work through an existing Terraform PR or
   controlled runbook, with validation and an audit trail.

Each future phase remains behind explicit human approval gates.
