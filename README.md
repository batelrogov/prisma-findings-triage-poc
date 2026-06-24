**Open-Source Reference Architecture & Disclaimer**
This repository contains an independent, open-source reference architecture developed entirely by the author to demonstrate general modern cloud infrastructure concepts. It is not affiliated with, derived from, or endorsed by any past or present employer. This code is provided as-is for educational and architectural purposes, and anyone (including global engineering teams, community members, or enterprises) is welcome to clone, adapt, and build upon it to solve their own specific infrastructure challenges.

# AWS Security AI Agent

An autonomous AI agent that audits AWS security configurations using Amazon Bedrock.
It collects EC2 Security Group ingress rules and S3 bucket public access settings,
asks a Bedrock LLM (Claude 3 Sonnet by default) to act as a Senior AWS Cloud
Security Auditor, and produces:

- A professional **Markdown audit report** (`audit_report.md`) with severity-rated
  findings and remediation steps.
- A **Terraform remediation snippet** (`remediation.tf`) that closes the discovered
  gaps (e.g. restricting port 22 from `0.0.0.0/0`, enabling S3 public access blocks).

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
| `trusted_cidr` | CIDR the remediation Terraform allows instead of `0.0.0.0/0`. | `10.0.0.0/8` |
| `output.report_path` | Markdown report output path. | `audit_report.md` |
| `output.terraform_path` | Terraform output path. | `remediation.tf` |

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
`remediation.tf` to the paths defined in `config.yaml`.

### Programmatic use

```python
from audit_agent import collect_aws_data, init_bedrock_llm, audit_and_remediate

raw_data = collect_aws_data(region_name="us-east-1")
llm = init_bedrock_llm()
results = audit_and_remediate(raw_data, llm=llm)
print(results["report"])
```

## How it works

1. `collect_aws_data()` — fetches Security Group ingress rules and S3 public
   access block settings into a single structured dict.
2. `analyze_security_data()` — sends the data to Bedrock with a strict auditor
   system prompt and returns a Markdown report.
3. `generate_remediation_terraform()` — produces Terraform HCL that remediates
   the findings.
4. `audit_and_remediate()` — orchestrates both and writes the output files.

## Disclaimer

The generated Terraform is a starting point. Always review it before applying it
to any environment with `terraform plan`.
