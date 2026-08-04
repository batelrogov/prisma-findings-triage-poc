**Open-Source Reference Architecture & Disclaimer**

This repository contains an independent, open-source proof of concept developed
for educational and architectural purposes. It is not affiliated with or
endorsed by any employer or product vendor.

# Prisma/Twistlock Findings Triage POC

A focused Phase 1 proof of concept for finding repeated pain points in large
Prisma Cloud and Twistlock reports. It classifies finding patterns as:

- **Recurring** — the same vulnerability or policy pattern affects multiple
  distinct resources and may justify a shared treatment.
- **Unique** — the pattern affects one resource and needs individual review.
- **Needs More Information** — the finding cannot be routed safely because its
  identity, resource, ownership, or management context is incomplete.

For vulnerability reports, the POC also rolls recurring CVEs into package/image
candidates. This highlights cases where one underlying package or image update
may address many findings, subject to compatibility and rollout review.

The POC does not remediate findings, change AWS resources, run scripts, update
images or packages, create Terraform, or replace Prisma.

## Why this exists

Large periodic reports can contain thousands of rows. Before remediation starts,
a reviewer must identify repeated patterns, distinguish duplicated rows from
distinct affected resources, and find the underlying changes that could address
multiple findings. This project makes that first-pass analysis consistent and
reviewable.

## Validated sample shape

The implementation has been exercised against a Twistlock hosts CSV containing
fields such as `Hostname`, `CVE ID`, `Type`, `Severity`, `Packages`,
`Source Package`, `Package Version`, `Fix Status`, `Account ID`, `Region`, and
`Resource ID`. The sample itself is not stored in this repository.

## Components

- `prisma_triage_engine.py` — deterministic CSV/XLSX reference implementation.
- `COPILOT_REVIEW_GUIDELINES.md` — guardrails and expected output for a future
  approved Microsoft Copilot review interface.
- `config.yaml` — distinct-resource threshold, column aliases, worksheet, and outputs.

## Installation

Python 3.9 or newer is required.

```bash
python -m pip install -r requirements.txt
```

## Usage

```bash
python prisma_triage_engine.py path/to/prisma-findings.csv
```

CSV and XLSX input are supported. The default outputs are:

- `triage_report.md` — prioritized patterns and package/image candidates.
- `categorized_findings.csv` — normalized rows plus category and suggested route.

The Markdown intentionally shows only the configured top candidates and patterns,
so the triage output does not recreate the original oversized report. The CSV
retains the complete row-level result for filtering and audit.

## Classification approach

For a vulnerability export, a pattern uses the CVE, package/component, installed
version, reported fix status, and resource type. A pattern is `Recurring` when it
affects at least `recurring_min_resources` distinct resources. Duplicate rows on
one resource do not make a pattern recurring.

Recurring vulnerability patterns are also grouped by package, installed version,
distribution, and resource type. This package/image view is the main input for
identifying automation opportunities: one controlled base-image or package update
may address multiple CVEs across multiple resources.

The tool does not automatically select the highest value found in `Fix Status`.
Different CVEs can report different target versions, and a supported target must
be chosen only after ownership, compatibility, testing, rollout, and rollback review.

## Suggested routes

- Repeated package findings may be package/image update candidates after confirming
  how hosts are provisioned and whether a shared template or image owns the version.
- A Terraform template route is valid only after code and state confirm ownership.
- A script-assisted route requires explicit scope, dry run, impact review, rollback,
  and approval.
- Unique findings remain with a resource owner for contextual review.
- Repeated provisioning problems may justify a preventive control.

## Safety boundaries

- The tool performs classification only.
- Absence of Terraform evidence means `Unknown`, not `Manual`.
- Reported fix versions and management fields are evidence to validate, not authority.
- All suggested routes are candidates, not approved remediation.
- Resource/image ownership, business impact, compatibility, dependencies, rollout,
  rollback, testing, and approval must be validated before any change.

## Roadmap

1. **Current:** report ingestion, normalization, resource-aware classification,
   package/image candidate discovery, and prioritization.
2. **Ownership enrichment:** connect findings to approved code/state, image pipeline,
   and owner data.
3. **Proposal generation:** prepare review-only remediation proposals.
4. **Read-only AWS MCP enrichment:** retrieve current resource context without changes.
5. **Governed lifecycle:** route approved work through an existing image pipeline,
   Terraform PR, or controlled runbook with validation and an audit trail.

Each future phase remains behind explicit human approval gates.
