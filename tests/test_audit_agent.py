import tempfile
import unittest
from pathlib import Path

from audit_agent import (
    REMEDIATION_PROPOSAL_SYSTEM_PROMPT,
    audit_and_propose,
    generate_remediation_proposal,
    load_config,
)


class FakeResponse:
    def __init__(self, content):
        self.content = content


class RecordingLLM:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def invoke(self, messages):
        self.calls.append(messages)
        return FakeResponse(next(self.responses))


class RemediationProposalTests(unittest.TestCase):
    def test_default_output_is_markdown_proposal(self):
        config = load_config("missing-config.yaml")
        self.assertEqual(
            config["output"]["proposal_path"], "remediation_proposal.md"
        )
        self.assertNotIn("terraform_path", config["output"])

    def test_prompt_contains_required_safety_boundaries(self):
        prompt = REMEDIATION_PROPOSAL_SYSTEM_PROMPT
        self.assertIn("DOES NOT remove or replace", prompt)
        self.assertIn("state/import", prompt)
        self.assertIn("business and availability impact", prompt)
        self.assertIn("terraform validate", prompt)
        self.assertIn("terraform plan", prompt)
        self.assertIn("human approver", prompt)

    def test_trusted_cidr_is_context_not_an_approved_value(self):
        llm = RecordingLLM(["# Draft remediation proposal"])
        result = generate_remediation_proposal(
            {}, llm=llm, trusted_cidr="192.0.2.0/24"
        )
        self.assertEqual(result, "# Draft remediation proposal")
        human_prompt = llm.calls[0][1].content
        self.assertIn("192.0.2.0/24", human_prompt)
        self.assertIn("require a reviewer to validate it", human_prompt)

    def test_orchestrator_writes_markdown_not_tf(self):
        llm = RecordingLLM(["# Audit", "# Draft proposal"])
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "audit.md"
            proposal_path = Path(directory) / "proposal.md"
            result = audit_and_propose(
                {},
                llm=llm,
                report_path=report_path,
                proposal_path=proposal_path,
            )
            self.assertEqual(report_path.read_text(), "# Audit")
            self.assertEqual(proposal_path.read_text(), "# Draft proposal")
            self.assertEqual(result["proposal"], "# Draft proposal")
            self.assertNotIn("terraform", result)


if __name__ == "__main__":
    unittest.main()
