"""Tests for the independent offline network-triage exercise."""
import copy
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "portfolio_demo"))
from triage import (  # noqa: E402
    DiagnosticInputError, analyze_document, load_document, main, validate_cases,
)

SAMPLE = ROOT / "portfolio_demo" / "sample_cases.json"


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(SAMPLE.read_text(encoding="utf-8"))

    def test_six_original_case_categories_have_independent_candidates(self):
        results = analyze_document(self.data)
        self.assertEqual(len(results), 6)
        observed = {r["id"]: [finding["code"] for finding in r["findings"]] for r in results}
        self.assertEqual(observed, {
            "suspicious-file-transfer": ["TRAFFIC_REVIEW"],
            "incorrect-dns-answer": ["DNS_MISMATCH"],
            "external-route-failure": ["REMOTE_PATH"],
            "invalid-endpoint-addressing": ["ADDRESSING_MISMATCH"],
            "dmz-firewall-denied": ["FIREWALL_POLICY"],
            "unexpected-listener": ["LISTENER_REVIEW"],
        })

    def test_no_mutation_of_input(self):
        before = copy.deepcopy(self.data)
        analyze_document(self.data)
        self.assertEqual(self.data, before)

    def test_unknown_measurements_do_not_become_negative_findings(self):
        case = self.data["cases"][0]
        case["observations"] = {k: None for k in case["observations"]}
        result = analyze_document({"cases": [case]})[0]
        self.assertEqual(result["status"], "NO_ANOMALY_CONFIRMED")
        self.assertEqual(len(result["missing_evidence"]), 9)

    def test_link_down_candidate(self):
        self.data["cases"][0]["observations"]["link_up"] = False
        codes = [f["code"] for f in analyze_document(self.data)[0]["findings"]]
        self.assertIn("LINK_DOWN", codes)

    def test_gateway_path_when_ip_config_is_plausible(self):
        self.data["cases"][0]["observations"]["gateway_reachable"] = False
        codes = [f["code"] for f in analyze_document(self.data)[0]["findings"]]
        self.assertIn("GATEWAY_PATH", codes)

    def test_no_gateway_path_inference_from_bad_ip_configuration(self):
        result = next(r for r in analyze_document(self.data) if r["id"] == "invalid-endpoint-addressing")
        self.assertNotIn("GATEWAY_PATH", [f["code"] for f in result["findings"]])

    def test_failed_application_port_without_firewall_log(self):
        obs = self.data["cases"][0]["observations"]
        obs["remote_ip_reachable"] = True
        obs["application_port_reachable"] = False
        obs["firewall_deny_logged"] = False
        codes = [f["code"] for f in analyze_document({"cases": [self.data["cases"][0]]})[0]["findings"]]
        self.assertIn("APPLICATION_PATH", codes)

    def test_firewall_log_takes_precedence_over_app_port_hypothesis(self):
        result = next(r for r in analyze_document(self.data) if r["id"] == "dmz-firewall-denied")
        self.assertNotIn("APPLICATION_PATH", [f["code"] for f in result["findings"]])

    def test_multiple_candidate_findings_are_preserved(self):
        obs = self.data["cases"][1]["observations"]
        obs["firewall_deny_logged"] = True
        result = analyze_document({"cases": [self.data["cases"][1]]})[0]
        self.assertEqual([f["code"] for f in result["findings"]], ["DNS_MISMATCH", "FIREWALL_POLICY"])

    def test_port_65535_is_accepted(self):
        self.data["cases"][5]["observations"]["unexpected_listening_ports"] = [65535]
        self.assertIn("LISTENER_REVIEW", [f["code"] for f in analyze_document(self.data)[5]["findings"]])

    def test_empty_cases_rejected(self):
        with self.assertRaisesRegex(DiagnosticInputError, "1-32"):
            validate_cases({"cases": []})

    def test_not_a_document_rejected(self):
        with self.assertRaisesRegex(DiagnosticInputError, "document"):
            validate_cases("hello")

    def test_non_object_case_rejected(self):
        self.data["cases"] = [None]
        with self.assertRaisesRegex(DiagnosticInputError, "object"):
            validate_cases(self.data)

    def test_duplicate_case_ids_rejected(self):
        self.data["cases"].append(copy.deepcopy(self.data["cases"][0]))
        with self.assertRaisesRegex(DiagnosticInputError, "duplicate case"):
            validate_cases(self.data)

    def test_invalid_case_id_rejected(self):
        self.data["cases"][0]["id"] = "../../etc/passwd"
        with self.assertRaisesRegex(DiagnosticInputError, "ASCII"):
            validate_cases(self.data)

    def test_missing_signal_rejected(self):
        self.data["cases"][0]["observations"].pop("link_up")
        with self.assertRaisesRegex(DiagnosticInputError, "missing signals"):
            validate_cases(self.data)

    def test_unknown_signal_rejected(self):
        self.data["cases"][0]["observations"]["invented_key"] = True
        with self.assertRaisesRegex(DiagnosticInputError, "unexpected signals"):
            validate_cases(self.data)

    def test_wrong_boolean_type_rejected(self):
        self.data["cases"][0]["observations"]["link_up"] = "false"
        with self.assertRaisesRegex(DiagnosticInputError, "true, false, or null"):
            validate_cases(self.data)

    def test_int_as_boolean_rejected(self):
        self.data["cases"][0]["observations"]["link_up"] = 1
        with self.assertRaises(DiagnosticInputError):
            validate_cases(self.data)

    def test_invalid_port_rejected(self):
        self.data["cases"][5]["observations"]["unexpected_listening_ports"] = [65536]
        with self.assertRaisesRegex(DiagnosticInputError, "ports"):
            validate_cases(self.data)

    def test_bool_port_rejected(self):
        self.data["cases"][5]["observations"]["unexpected_listening_ports"] = [True]
        with self.assertRaisesRegex(DiagnosticInputError, "ports"):
            validate_cases(self.data)

    def test_duplicate_port_rejected(self):
        self.data["cases"][5]["observations"]["unexpected_listening_ports"] = [22, 22]
        with self.assertRaisesRegex(DiagnosticInputError, "unique"):
            validate_cases(self.data)

    def test_unhashable_port_rejected_safely(self):
        self.data["cases"][5]["observations"]["unexpected_listening_ports"] = [{"port": 22}]
        with self.assertRaises(DiagnosticInputError):
            validate_cases(self.data)

    def test_null_listeners_represents_uncollected_evidence(self):
        self.data["cases"][5]["observations"]["unexpected_listening_ports"] = None
        result = analyze_document(self.data)[5]
        self.assertIn("unexpected_listening_ports", result["missing_evidence"])

    def test_invalid_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{not valid", encoding="utf-8")
            with self.assertRaisesRegex(DiagnosticInputError, "valid UTF-8 JSON"):
                load_document(path)

    def test_file_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b"x" * (128 * 1024 + 1))
            with self.assertRaisesRegex(DiagnosticInputError, "128 KiB"):
                load_document(path)

    def test_json_cli(self):
        with StringIO() as capture:
            with redirect_stdout(capture):
                status = main(["--json"])
            response = json.loads(capture.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(response["mode"], "offline_triage")
        self.assertEqual(len(response["cases"]), 6)

    def test_human_cli(self):
        with StringIO() as capture:
            with redirect_stdout(capture):
                status = main([])
            output = capture.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("hypotheses, not verified root causes", output)


if __name__ == "__main__":
    unittest.main()
