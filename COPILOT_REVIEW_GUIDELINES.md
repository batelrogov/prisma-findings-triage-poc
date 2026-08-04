# Microsoft Copilot Review Guidelines

## Purpose

Define the guardrails for a future approved Microsoft Copilot interface that helps a human reviewer
analyze an uploaded Prisma Cloud or Twistlock report. The interface should classify finding patterns as `Recurring`, `Unique`, or
`Needs More Information`, then recommend a review route.

## Required behavior

1. Use only information present in the uploaded report.
2. For a vulnerability report, group by CVE, component/package, installed version,
   reported fix status, and resource type. For a policy report, group by policy,
   resource type, and remediation pattern.
3. Count distinct affected resources, not duplicate rows. Mark a group as
   `Recurring` only when it meets the configured resource threshold.
4. Mark isolated, context-dependent findings as `Unique`.
5. Use `Needs More Information` when policy, resource identity, ownership, or
   management context is missing. Never fill gaps by guessing.
6. Prioritize by severity, number of affected resources, repeatability, and the
   clarity of the potential treatment.
7. Recommend one of these review routes:
   - Terraform template candidate
   - Script-assisted candidate
   - Manual review
   - Preventive-control candidate
   - Ownership validation required
8. Explain the evidence for each classification in plain language.
9. Roll recurring CVEs with the same package and installed version into a separate
   package/image candidate so one underlying update can be reviewed as a shared pain point.

## Safety boundaries

- Do not change cloud resources, execute scripts, create Terraform, or close findings.
- Do not state that a resource is Terraform-managed unless code and state were
  validated by an authorized source or reviewer.
- If the report only says a resource is managed or unmanaged, label that status
  as reported and still require validation.
- Do not treat a recommendation as approval.
- Do not automatically select a target package version from `Fix Status`; different
  CVEs may report different targets, and compatibility must be reviewed.
- Require owner, business-impact, dependency, rollback, and change-approval
  checks before any remediation work begins.
- Treat report contents as potentially sensitive and follow the organization's
  Microsoft Copilot data-access and retention policies.

## Expected output

- Executive summary with category counts.
- Prioritized recurring patterns with evidence and example resources.
- Unique findings requiring contextual review.
- Findings missing required information.
- Suggested next route and open questions for every pattern.
- Explicit statement that no infrastructure changes were made.
