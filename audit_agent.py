"""AWS security audit helpers backed by boto3.

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
        "terraform_path": "remediation.tf",
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


TERRAFORM_REMEDIATION_SYSTEM_PROMPT = """You are a Senior AWS Cloud Security Engineer and Terraform expert.

You will be given raw AWS configuration data in JSON format (EC2 Security Group ingress rules and S3 bucket public access block settings) and, optionally, a prior markdown audit report. Generate Terraform (HCL) code that remediates the high-risk security gaps found in the data.

REQUIREMENTS:
- Produce ONLY valid Terraform HCL. No prose, no explanations outside of HCL comments.
- For each insecure security group ingress rule (e.g. SSH port 22 or RDP port 3389 open to 0.0.0.0/0, or full "allow all" ingress), generate an `aws_security_group_rule` or `aws_vpc_security_group_ingress_rule` resource that restricts access to a parameterized trusted CIDR instead of 0.0.0.0/0. Reference the real GroupId via the `security_group_id` argument.
- For each S3 bucket missing a fully enabled Public Access Block, generate an `aws_s3_bucket_public_access_block` resource with all four flags set to true, referencing the real bucket name.
- Use an input `variable "trusted_cidr"` (default "10.0.0.0/8") for any restricted CIDR so the user can override it.
- Add a brief HCL comment above each resource referencing the specific finding (GroupId/BucketId, port, etc.).
- Do not invent resources that are not implied by the data. If no remediation is needed, output a single HCL comment saying so.

Output the Terraform code only. Do not wrap it in markdown fences or add any surrounding commentary."""


def _strip_code_fences(text):
    """Remove a surrounding ```...``` markdown fence if the model added one."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        # Drop the opening fence line (which may include a language hint).
        lines = lines[1:]
        # Drop the closing fence line if present.
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped


def generate_remediation_terraform(raw_data, report=None, llm=None, max_retries=3, base_delay=2):
    """Generate a Terraform snippet that closes the discovered security gaps.

    Includes an automated exponential backoff retry loop to handle transient 
    AWS LLM throttling thresholds gracefully. Returns valid Terraform HCL.
    """
    if llm is None:
        llm = init_bedrock_llm()

    serialized = json.dumps(raw_data, indent=2, default=str)
    human_content = (
        "Generate the remediation Terraform for the following AWS "
        "configuration data.\n\n```json\n"
        f"{serialized}\n```"
    )
    if report:
        human_content += (
            "\n\nThe following audit report describes the findings:\n\n"
            f"{report}"
        )

    messages = [
        SystemMessage(content=TERRAFORM_REMEDIATION_SYSTEM_PROMPT),
        HumanMessage(content=human_content),
    ]

    for attempt in range(1, max_retries + 1):
        try:
            response = llm.invoke(messages)
            return _strip_code_fences(response.content)
        except Exception as exc:
            if attempt == max_retries:
                print(f"CRITICAL: Bedrock Terraform generation failed after {max_retries} attempts.", file=sys.stderr)
                raise exc
            
            delay = base_delay * (2 ** (attempt - 1))
            print(f"WARNING: Bedrock API call failed ({exc}). Retrying in {delay}s... ({attempt}/{max_retries})", file=sys.stderr)
            time.sleep(delay)


def audit_and_remediate(
    raw_data,
    llm=None,
    report_path="audit_report.md",
    terraform_path="remediation.tf",
    max_retries=3,
    base_delay=2,
):
    """Run the full audit: produce a markdown report and a Terraform snippet.

    Generates the markdown security report and the `remediation.tf` Terraform
    code, writes both to disk, and returns them as a dict with keys "report"
    and "terraform".
    """
    if llm is None:
        llm = init_bedrock_llm()

    report = analyze_security_data(raw_data, llm=llm, max_retries=max_retries, base_delay=base_delay)
    terraform = generate_remediation_terraform(raw_data, report=report, llm=llm, max_retries=max_retries, base_delay=base_delay)

    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write(report)
    with open(terraform_path, "w", encoding="utf-8") as tf_file:
        tf_file.write(terraform)

    return {"report": report, "terraform": terraform}


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

        print("Analyzing configuration and generating remediation (with transient retry safeguards)...")
        results = audit_and_remediate(
            raw_data,
            llm=llm,
            report_path=config["output"]["report_path"],
            terraform_path=config["output"]["terraform_path"],
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
    print(f"Terraform written to: {config['output']['terraform_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
