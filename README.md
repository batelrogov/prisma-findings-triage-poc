**Open-Source Reference Architecture & Disclaimer**
This repository contains an independent, open-source reference architecture developed entirely by the author to demonstrate general modern cloud infrastructure concepts. It is not affiliated with, derived from, or endorsed by any past or present employer. This code is provided as-is for educational and architectural purposes, and anyone (including global engineering teams, community members, or enterprises) is welcome to clone, adapt, and build upon it to solve their own specific infrastructure challenges.

# Bedrock-Assisted AWS Security Audit POC

This focused proof of concept explores whether repeated AWS configuration-review
work can be collected and organized with help from Amazon Bedrock. It currently
covers two intentionally narrow controls: EC2 Security Group ingress rules and
S3 Public Access Block settings.

It is not an autonomous remediation system and is not a replacement for AWS
Security Hub, AWS Config, or a Cloud Security Posture Management (CSPM) platform.
It produces:

- A professional **Markdown audit report** (`audit_report.md`) with severity-rated
  findings and remediation steps.
- A human-reviewable **draft remediation proposal**
  (`remediation_proposal.md`) that may contain unvalidated candidate Terraform.

## Safety boundaries

- The tool only reads AWS configuration and invokes Bedrock. It does not modify
  AWS resources or run Terraform.
- Generated findings and remediation are AI-assisted drafts and may be incomplete
  or incorrect.
- A restrictive Security Group rule does **not** remove an existing permissive
  rule. Existing exposure must be identified and deliberately removed only after
  validating ownership, dependencies, and required access.
- Before using any candidate Terraform, a human must confirm resource ownership,
  existing Terraform/state/import strategy, trusted CIDRs, and business impact;
  prepare rollback steps; run `terraform fmt`, `terraform validate`, and
  `terraform plan`; review the plan; and obtain security/change approval.
- Never apply generated code directly to an environment.

## Requirements

- Python 3.9+
- AWS credentials with read access to EC2/S3 and Bedrock model invocation
- Amazon Bedrock model access enabled for the configured model in your region

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Settings live in `config.yaml`:

| Key | Description | Default |
| --- | --- | --- |
| `region` | AWS region for the audit and Bedrock. `null` uses your profile default. | `null` |
| `model_id` | Bedrock model id used for analysis. | `anthropic.claude-3-sonnet-20240229-v1:0` |
| `temperature` | LLM temperature (0 = deterministic). | `0` |
| `trusted_cidr` | Example CIDR included in the draft; it must be validated by an owner. | `10.0.0.0/8` |
| `output.report_path` | Markdown report output path. | `audit_report.md` |
| `output.proposal_path` | Draft Markdown proposal output path. | `remediation_proposal.md` |

## AWS credentials

Provide credentials via any standard mechanism:

```bash
aws configure
# or environment variables:
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

### Minimum IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "bedrock:InvokeModel"
      ],
      "Resource": "*"
    }
  ]
}
```

## Usage

Run the full audit end to end:

```bash
python audit_agent.py
```

This collects AWS data, runs the analysis, and writes `audit_report.md` and
`remediation_proposal.md` to the paths defined in `config.yaml`. It does not
apply changes.

### Programmatic use

```python
from audit_agent import collect_aws_data, init_bedrock_llm, audit_and_propose

raw_data = collect_aws_data(region_name="us-east-1")
llm = init_bedrock_llm()
results = audit_and_propose(raw_data, llm=llm)
print(results["report"])
```

## How it works

1. `collect_aws_data()` — fetches Security Group ingress rules and S3 public
   access block settings into a single structured dict.
2. `analyze_security_data()` — sends the data to Bedrock with a strict auditor
   system prompt and returns a Markdown report.
3. `generate_remediation_proposal()` — produces a Markdown draft with review
   questions, mandatory validation steps, and optional candidate Terraform.
4. `audit_and_propose()` — orchestrates both and writes the output files.

## Disclaimer

This educational POC has intentionally limited coverage. Its output is not a
security certification and should not be treated as production-ready change
automation. Candidate code requires the complete human review described above.
