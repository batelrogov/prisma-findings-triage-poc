import csv
import tempfile
import unittest
from pathlib import Path

from openpyxl import Workbook

from prisma_triage_agent import DEFAULT_CONFIG, classify_findings, normalize_findings, render_report, run_triage


def finding(resource_id, finding_id="CVE-2026-0001", **values):
    return {
        "finding_id": finding_id,
        "resource_id": resource_id,
        "resource_name": values.get("resource_name", ""),
        "resource_type": values.get("resource_type", "OS"),
        "severity": values.get("severity", "High"),
        "component": values.get("component", "openssl"),
        "installed_version": values.get("installed_version", "1.0"),
        "fix_status": values.get("fix_status", "fixed in 1.1"),
        "distro": values.get("distro", "AL2023"),
        "account": values.get("account", "dev"),
        "region": values.get("region", "us-east-1"),
        "cluster": values.get("cluster", "cluster-a"),
        "description": values.get("description", "Example vulnerability"),
        "owner": values.get("owner", ""),
        "terraform_status": values.get("terraform_status", ""),
    }


class PrismaTriageTests(unittest.TestCase):
    def test_pattern_on_two_resources_is_recurring(self):
        result = classify_findings([finding("i-1"), finding("i-2")], 2)
        self.assertEqual(result["counts"], {"Recurring": 2})
        self.assertEqual(result["patterns"][0]["resource_count"], 2)

    def test_duplicate_rows_on_one_resource_are_unique(self):
        result = classify_findings([finding("i-1"), finding("i-1")], 2)
        self.assertEqual(result["counts"], {"Unique": 2})
        self.assertEqual(result["patterns"][0]["resource_count"], 1)

    def test_missing_identity_needs_information(self):
        result = classify_findings([finding("")], 2)
        self.assertEqual(result["counts"], {"Needs More Information": 1})

    def test_hostname_is_resource_fallback(self):
        result = classify_findings(
            [finding("", resource_name="host-1"), finding("", resource_name="host-2")], 2
        )
        self.assertEqual(result["counts"], {"Recurring": 2})

    def test_absent_terraform_evidence_remains_unknown(self):
        result = classify_findings([finding("i-1"), finding("i-2")], 2)
        self.assertEqual(
            result["patterns"][0]["management_status"],
            "Unknown — ownership validation required",
        )

    def test_twistlock_headers_are_normalized(self):
        rows = [{
            "CVE ID": "CVE-2026-0001", "Resource ID": "i-1", "Hostname": "host-1",
            "Type": "OS", "Source Package": "openssl", "Package Version": "1.0",
            "Fix Status": "fixed in 1.1",
        }]
        normalized = normalize_findings(rows, DEFAULT_CONFIG["column_aliases"])
        self.assertEqual(normalized[0]["finding_id"], "CVE-2026-0001")
        self.assertEqual(normalized[0]["component"], "openssl")
        self.assertEqual(normalized[0]["resource_id"], "i-1")

    def test_multiple_cves_roll_up_to_one_automation_candidate(self):
        rows = [finding("i-1", "CVE-1"), finding("i-2", "CVE-1"), finding("i-1", "CVE-2"), finding("i-2", "CVE-2")]
        result = classify_findings(rows, 2)
        self.assertEqual(len(result["automation_candidates"]), 1)
        self.assertEqual(result["automation_candidates"][0]["finding_count"], 2)
        self.assertEqual(result["automation_candidates"][0]["resource_count"], 2)

    def test_report_contains_safety_statement(self):
        report = render_report(classify_findings([finding("i-1")], 2))
        self.assertIn("No cloud resources, scripts, images, packages, or Terraform changes", report)
        self.assertIn("not an automatically selected target", report)

    def test_csv_workflow_writes_both_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, report, categorized, config = root / "input.csv", root / "report.md", root / "categorized.csv", root / "config.yaml"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["CVE ID", "Resource ID", "Type", "Packages"])
                writer.writeheader()
                writer.writerow({"CVE ID": "CVE-1", "Resource ID": "i-1", "Type": "OS", "Packages": "pkg"})
            config.write_text(f"output:\n  report_path: {report}\n  categorized_path: {categorized}\n", encoding="utf-8")
            result = run_triage(source, config)
            self.assertEqual(result["total"], 1)
            self.assertTrue(report.exists())
            self.assertTrue(categorized.exists())

    def test_xlsx_workflow_reads_active_sheet(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, report, categorized, config = root / "input.xlsx", root / "report.md", root / "categorized.csv", root / "config.yaml"
            workbook = Workbook()
            worksheet = workbook.active
            worksheet.append(["CVE ID", "Resource ID", "Type", "Packages"])
            worksheet.append(["CVE-1", "i-1", "OS", "pkg"])
            workbook.save(source)
            config.write_text(f"output:\n  report_path: {report}\n  categorized_path: {categorized}\n", encoding="utf-8")
            self.assertEqual(run_triage(source, config)["counts"], {"Unique": 1})


if __name__ == "__main__":
    unittest.main()
