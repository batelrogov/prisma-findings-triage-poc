"""AWS security audit POC helpers backed by boto3.

These functions collect AWS configuration data in a structured form that an
LLM (e.g. via Amazon Bedrock) can parse and reason about later.
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
from langchain_aws import ChatBedrock
from langchain_core.messages import HumanMessage, SystemMessage
import json
import os
import sys
import time
import yaml

# Default Bedrock model used for analytical security reasoning.
BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet-20240229-v1:0"

# Default configuration applied when config.yaml is missing or partial.
DEFAULT_CONFIG = {
    "region": None,
    "model_id": BEDROCK_MODEL_ID,
    "temperature": 0,
    "trusted_cidr": "10.0.0.0/8",
    "max_llm_retries": 3,          # New: Max attempts for transient LLM API rate limits
    "llm_retry_delay_seconds": 2,  # New: Base delay for exponential backoff
    "output": {
        "report_path": "audit_report.md",
        "proposal_path": "remediation_proposal.md",
    },
}


def load_config(config_path="config.yaml"):
    """Load agent configuration from a YAML file, merged over sane defaults.

    Missing files or missing keys fall back to `DEFAULT_CONFIG`, so the agent
    runs even without a config file present.
    """
    config = {**DEFAULT_CONFIG, "output": {**DEFAULT_CONFIG["output"]}}

    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as config_file:
            loaded = yaml.safe_load(config_file) or {}
        for key, value in loaded.items():
            if key == "output" and isinstance(value, dict):
                config["output"].update(value)
            else:
                config[key] = value

    return config


def init_bedrock_llm(model_id=BEDROCK_MODEL_ID, region_name=None, temperature=0):
    """Initialize the Amazon Bedrock chat model for security analysis.

    Uses `ChatBedrock` from `langchain_aws`. Temperature defaults to 0 for
    strict, deterministic analytical reasoning. Returns a ready-to-use
    `ChatBedrock` instance.
    """
    client = boto3.client("bedrock-runtime", region_name=region_name)
    return ChatBedrock(
        client=client,
        model_id=model_id,
        model_kwargs={"temperature": temperature},
    )


def get_aws_security_groups(region_name=None):
    """List all EC2 Security Groups and return their ingress rules.

    Returns a list of dictionaries, one per security group, each containing the
    group identity and its inbound (ingress) permissions as returned by the
    EC2 API. The raw `IpPermissions` structure is preserved so no rule detail
    is lost before the data reaches the LLM.
    """
    ec2 = boto3.client("ec2", region_name=region_name)

    security_groups = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            security_groups.append(
                {
                    "GroupId": sg.get("GroupId"),
                    "GroupName": sg.get("GroupName"),
                    "Description": sg.get("Description"),
                    "VpcId": sg.get("VpcId"),
                    "IngressRules": sg.get("IpPermissions", []),
                }
            )

    return security_groups


def get_s3_bucket_policies(region_name=None):
    """List all S3 buckets and check whether public access block is enabled.

    Returns a list of dictionaries, one per bucket, describing the bucket name
    and its Public Access Block configuration. When no configuration exists,
    `PublicAccessBlockEnabled` is False and `PublicAccessBlockConfiguration`
    is None so the absence is explicit and machine-readable.
    """
    s3 = boto3.client("s3", region_name=region_name)

    buckets_info = []
    response = s3.list_buckets()
    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]
        entry = {
            "BucketName": bucket_name,
            "PublicAccessBlockEnabled": False,
            "PublicAccessBlockConfiguration": None,
        }

        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            config = pab.get("PublicAccessBlockConfiguration", {})
            entry["PublicAccessBlockConfiguration"] = config
            entry["PublicAccessBlockEnabled"] = all(
                [
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]
            )
        except ClientError as error:
            error_code = error.response["Error"]["Code"]
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                # No public access block is configured for this bucket.
                entry["PublicAccessBlockConfiguration"] = None
            else:
                entry["Error"] = error_code

        buckets_info.append(entry)

    return buckets_info


SECURITY_AUDITOR_SYSTEM_PROMPT = """You are a Senior AWS Cloud Security Auditor with deep expertise in the AWS Well-Architected Framework, CIS AWS Foundations Benchmark, and cloud threat modeling.

You will be given raw AWS configuration data in JSON format (EC2 Security Group ingress rules and S3 bucket public access block settings). Analyze it rigorously and produce a professional security audit report.

ANALYSIS REQUIREMENTS:
- Identify HIGH-RISK violations. Treat the following as critical:
  - Administrative/sensitive ports open to the world (0.0.0.0/0 or ::/0), especially SSH (22), RDP (3389), database ports (3306, 5432, 1433, 27017), and Redis/Elasticsearch/etc.
  - Any "allow all" ingress (IpProtocol "-1", or full port range 0-65535) from 0.0.0.0/0.
  - S3 buckets without a fully enabled Public Access Block (all four flags must be true).
- Classify each finding by severity: CRITICAL, HIGH, MEDIUM, or LOW.
- Be precise: reference the exact GroupId/GroupName, port, protocol, CIDR, or BucketName involved.
- Do not invent resources or rules that are not present in the data. If the data is empty, state that clearly.

OUTPUT FORMAT (Markdown only):
# AWS Security Audit Report

## Executive Summary
A short paragraph summarizing overall posture and the count of findings by severity.

## Findings
For each finding use this structure:
### [SEVERITY] <Concise title>
- **Resource:** <identifier>
- **Issue:** <what is wrong>
- **Risk:** <why it matters / potential impact>
- **Remediation:** <specific, actionable steps, including AWS CLI or console guidance>

## Recommendations
A prioritized, bulleted list of next actions.

SAFETY BOUNDARIES:
- This is a focused proof of concept, not a replacement for AWS Security Hub,
  AWS Config, or a CSPM platform.
- Do not claim that any change has been applied. Recommendations are advisory
  drafts that require resource-owner review and approval.

Be factual, concise, and strictly analytical. Do not include any text outside the markdown report."""


def analyze_security_data(raw_data, llm=None, max_retries=3, base_delay=2):
    """Analyze fetched AWS configuration data with the Bedrock LLM.

    Includes an automated exponential backoff retry loop to safeguard against
    transient API rate limiting (ThrottlingException) in production.
    Returns the LLM's markdown report as a string.
    """
    if llm is None:
        llm = init_bedrock_llm()

    serialized = json.dumps(raw_data, indent=2, default=str)
    messages = [
        SystemMessage(content=SECURITY_AUDITOR_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                "Audit the following AWS configuration data and produce the "
                "report as instructed.\n\n```json\n"
                f"{serialized}\n```"
            )
        ),
    ]

    for attempt in range(1, max_retries + 1):
        try:
            response = llm.invoke(messages)
            return response.content
        except Exception as exc:
            if attempt == max_retries:
                print(f"CRITICAL: Bedrock model invocation failed after {max_retries} attempts.", file=sys.stderr)
                raise exc
            
            # Calculate exponential delay: 2s, 4s, 8s...
            delay = base_delay * (2 ** (attempt - 1))
            print(f"WARNING: Bedrock API call failed ({exc}). Retrying in {delay}s... ({attempt}/{max_retries})", file=sys.stderr)
            time.sleep(delay)


REMEDIATION_PROPOSAL_SYSTEM_PROMPT = """You are a Senior AWS Cloud Security Engineer and Terraform expert.

You will be given raw AWS configuration data in JSON format (EC2 Security Group ingress rules and S3 bucket public access block settings) and, optionally, a prior markdown audit report. Generate a human-reviewable remediation proposal. It is a draft, not apply-ready remediation.

REQUIREMENTS:
- Produce Markdown with these sections: Draft status, proposed changes, candidate Terraform, mandatory validation checklist, and approval record.
- Label all Terraform as unvalidated candidate code and place it in a fenced HCL block.
- For each insecure security group ingress rule, explain that adding a restrictive rule DOES NOT remove or replace an existing permissive rule. Identify the permissive rule that would need separate, deliberate removal or revocation after ownership, dependencies, and access requirements are verified. Prefer proposing that the existing rule be imported and changed in its owning Terraform configuration; do not present a second restrictive rule as remediation. Never claim the candidate Terraform closes the exposure merely by adding a restrictive rule.
- Do not guess whether existing resources or rules are already Terraform-managed. Flag import, state ownership, resource-address, provider-version, and configuration-conflict checks for a human reviewer.
- For each S3 bucket missing a fully enabled Public Access Block, generate an `aws_s3_bucket_public_access_block` resource with all four flags set to true, referencing the real bucket name.
- Use an input `variable "trusted_cidr"` with the supplied draft default for restricted-access examples. State that the CIDR must be validated against actual administrative access requirements.
- Do not invent resources or identifiers. If information is insufficient, record an open question instead of guessing.
- The mandatory checklist must require: resource owner confirmation; Terraform state/import and existing-code ownership checks; business and availability impact review; verification of trusted CIDRs and dependencies; backup/rollback planning; `terraform fmt`, `terraform validate`, and review of `terraform plan`; security/change-management approval; and post-change verification.
- State explicitly that no generated command or code should be applied until every required check is complete and a human approver signs off.

Do not present the proposal as approved, complete, or safe to apply."""


def generate_remediation_proposal(
    raw_data,
    report=None,
    llm=None,
    trusted_cidr="10.0.0.0/8",
    max_retries=3,
    base_delay=2,
):
    """Generate a human-reviewed Markdown remediation proposal.

    Includes an automated exponential backoff retry loop to handle transient 
    AWS LLM throttling thresholds gracefully. Any Terraform included in the
    result is explicitly unvalidated candidate code.
    """
    if llm is None:
        llm = init_bedrock_llm()

    serialized = json.dumps(raw_data, indent=2, default=str)
    human_content = (
        "Create a DRAFT remediation proposal for the following AWS "
        "configuration data. No changes have been approved or applied. "
        f"The configured draft trusted CIDR is {trusted_cidr!r}; require a "
        "reviewer to validate it.\n\n```json\n"
        f"{serialized}\n```"
    )
    if report:
        human_content += (
            "\n\nThe following audit report describes the findings:\n\n"
            f"{report}"
        )

    messages = [
        SystemMessage(content=REMEDIATION_PROPOSAL_SYSTEM_PROMPT),
        HumanMessage(content=human_content),
    ]

    for attempt in range(1, max_retries + 1):
        try:
            response = llm.invoke(messages)
            return response.content.strip()
        except Exception as exc:
            if attempt == max_retries:
                print(f"CRITICAL: Bedrock proposal generation failed after {max_retries} attempts.", file=sys.stderr)
                raise exc
            
            delay = base_delay * (2 ** (attempt - 1))
            print(f"WARNING: Bedrock API call failed ({exc}). Retrying in {delay}s... ({attempt}/{max_retries})", file=sys.stderr)
            time.sleep(delay)


def audit_and_propose(
    raw_data,
    llm=None,
    report_path="audit_report.md",
    proposal_path="remediation_proposal.md",
    trusted_cidr="10.0.0.0/8",
    max_retries=3,
    base_delay=2,
):
    """Run the POC audit and produce two human-readable Markdown documents.

    The remediation proposal may contain candidate Terraform, but does not
    apply changes and is not an apply-ready Terraform configuration.
    """
    if llm is None:
        llm = init_bedrock_llm()

    report = analyze_security_data(raw_data, llm=llm, max_retries=max_retries, base_delay=base_delay)
    proposal = generate_remediation_proposal(
        raw_data,
        report=report,
        llm=llm,
        trusted_cidr=trusted_cidr,
        max_retries=max_retries,
        base_delay=base_delay,
    )

    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write(report)
    with open(proposal_path, "w", encoding="utf-8") as proposal_file:
        proposal_file.write(proposal)

    return {"report": report, "proposal": proposal}


def collect_aws_data(region_name=None):
    """Gather all audited AWS configuration into a single raw_data dict."""
    return {
        "security_groups": get_aws_security_groups(region_name=region_name),
        "s3_buckets": get_s3_bucket_policies(region_name=region_name),
    }


def main():
    """Run the agent end to end: collect AWS data, audit, and remediate."""
    config = load_config()
    region = config.get("region")
    max_retries = int(config.get("max_llm_retries", 3))
    base_delay = int(config.get("llm_retry_delay_seconds", 2))

    try:
        print("Collecting AWS security configuration...")
        raw_data = collect_aws_data(region_name=region)

        print("Initializing Amazon Bedrock model...")
        llm = init_bedrock_llm(
            model_id=config.get("model_id", BEDROCK_MODEL_ID),
            region_name=region,
            temperature=config.get("temperature", 0),
        )

        print("Analyzing configuration and generating a draft remediation proposal...")
        results = audit_and_propose(
            raw_data,
            llm=llm,
            report_path=config["output"]["report_path"],
            proposal_path=config["output"]["proposal_path"],
            trusted_cidr=config.get("trusted_cidr", "10.0.0.0/8"),
            max_retries=max_retries,
            base_delay=base_delay,
        )
    except NoCredentialsError:
        print(
            "ERROR: No AWS credentials found. Configure them via `aws configure`, "
            "environment variables, or an IAM role before running.",
            file=sys.stderr,
        )
        return 1
    except ClientError as error:
        print(f"ERROR: AWS API call failed: {error}", file=sys.stderr)
        return 1
    except BotoCoreError as error:
        print(f"ERROR: AWS SDK error: {error}", file=sys.stderr)
        return 1

    print(f"\nReport written to: {config['output']['report_path']}")
    print(f"Draft remediation proposal written to: {config['output']['proposal_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
