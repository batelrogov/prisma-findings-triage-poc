import csv
import tempfile
import unittest
from pathlib import Path

from openpyxl import Workbook

from prisma_triage_agent import (
    DEFAULT_CONFIG,
    classify_findings,
    normalize_findings,
    render_report,
    run_triage,
)


def finding(resource_id, policy="Open SSH", resource_type="Security Group", **values):
    return {
        "policy": policy,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "severity": values.get("severity", "High"),
        "account": values.get("account", "dev"),
        "region": values.get("region", "us-east-1"),
        "description": values.get("description", "SSH is open"),
        "remediation": values.get("remediation", "Restrict SSH"),
        "owner": values.get("owner", ""),
        "terraform_status": values.get("terraform_status", ""),
    }


class PrismaTriageTests(unittest.TestCase):
    def test_repeated_pattern_is_recurring(self):
        result = classify_findings(
            [finding("sg-1"), finding("sg-2"), finding("sg-3")],
            recurring_min_count=3,
        )
        self.assertEqual(result["counts"], {"Recurring": 3})
        self.assertEqual(result["patterns"][0]["category"], "Recurring")

    def test_small_pattern_is_unique(self):
        result = classify_findings([finding("sg-1")], recurring_min_count=3)
        self.assertEqual(result["counts"], {"Unique": 1})

    def test_missing_identity_needs_information(self):
        result = classify_findings([finding("")], recurring_min_count=3)
        self.assertEqual(result["counts"], {"Needs More Information": 1})

    def test_absent_terraform_evidence_remains_unknown(self):
        result = classify_findings(
            [finding("sg-1"), finding("sg-2"), finding("sg-3")], 3
        )
        pattern = result["patterns"][0]
        self.assertEqual(
            pattern["management_status"], "Unknown — ownership validation required"
        )
        self.assertIn("Validate ownership", pattern["suggested_route"])

    def test_column_aliases_are_normalized(self):
        rows = [{"Policy Name": "Public bucket", "Resource ID": "bucket-a"}]
        normalized = normalize_findings(rows, DEFAULT_CONFIG["column_aliases"])
        self.assertEqual(normalized[0]["policy"], "Public bucket")
        self.assertEqual(normalized[0]["resource_id"], "bucket-a")

    def test_report_contains_safety_statement(self):
        result = classify_findings([finding("sg-1")], 3)
        report = render_report(result)
        self.assertIn("No cloud resources, scripts, or Terraform changes were executed", report)
        self.assertIn("absence of evidence means `Unknown`, not `Manual`", report)

    def test_csv_workflow_writes_both_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.csv"
            report = root / "report.md"
            categorized = root / "categorized.csv"
            config = root / "config.yaml"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=["Policy Name", "Resource ID", "Resource Type"]
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "Policy Name": "Public bucket",
                        "Resource ID": "bucket-a",
                        "Resource Type": "S3 Bucket",
                    }
                )
            config.write_text(
                "output:\n"
                f"  report_path: {report}\n"
                f"  categorized_path: {categorized}\n",
                encoding="utf-8",
            )
            result = run_triage(source, config)
            self.assertEqual(result["total"], 1)
            self.assertTrue(report.exists())
            self.assertTrue(categorized.exists())

    def test_xlsx_workflow_reads_active_sheet(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.xlsx"
            report = root / "report.md"
            categorized = root / "categorized.csv"
            config = root / "config.yaml"
            workbook = Workbook()
            worksheet = workbook.active
            worksheet.append(["Policy Name", "Resource ID", "Resource Type"])
            worksheet.append(["Public bucket", "bucket-a", "S3 Bucket"])
            workbook.save(source)
            config.write_text(
                "output:\n"
                f"  report_path: {report}\n"
                f"  categorized_path: {categorized}\n",
                encoding="utf-8",
            )
            result = run_triage(source, config)
            self.assertEqual(result["total"], 1)
            self.assertEqual(result["counts"], {"Unique": 1})


if __name__ == "__main__":
    unittest.main()
