"""Kiểm thử Trust Evaluation Engine. Chạy: python -m unittest discover -s tests -t . -v"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from tests import fixtures as fx
from trust_engine.__main__ import main
from trust_engine.engine import evaluate
from trust_engine.evidence import load_evidence
from trust_engine.policy import PolicyError, load_policy

POLICY_DIR = Path(__file__).resolve().parents[1] / "policy"
NOW = datetime.fromisoformat(fx.NOW.replace("Z", "+00:00"))


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.policy = load_policy(POLICY_DIR / "default.yaml")

    def tearDown(self):
        self.tmp.cleanup()

    def run_case(self, evidence: dict, policy: dict | None = None) -> dict:
        fx.write(evidence, self.root / "ev")
        return evaluate(policy or self.policy, load_evidence(self.root / "ev"), now=NOW)

    def violation_ids(self, d: dict) -> set[str]:
        return {v["id"] for v in d["violations"]}

    # ---------------------------------------------------- kịch bản đề cương
    def test_01_valid_artifact_is_allowed(self):
        d = self.run_case(fx.valid_evidence())
        self.assertEqual(d["decision"], "ALLOWED", d["violations"])
        self.assertEqual(d["trust_level"], "TRUSTED")
        self.assertEqual(d["artifact"]["digest_source"], "verification.json")

    def test_02_critical_vulnerability_is_blocked(self):
        ev = fx.valid_evidence()
        v = fx.vuln(["CRITICAL", "HIGH", "MEDIUM"])
        ev["vuln-verify.json"] = fx.dsse("https://cosign.sigstore.dev/attestation/vuln/v1", v)
        ev["vuln.cosign.json"] = v
        d = self.run_case(ev)
        self.assertEqual(d["decision"], "BLOCKED")
        self.assertEqual(self.violation_ids(d), {"VULN-002"})

    def test_03_missing_signature_is_blocked(self):
        ev = fx.valid_evidence()
        ev["verification.json"].update(skip_sign=True, signature_verification="failure")
        ev["signature-verify.json"] = ""  # cosign verify lỗi => file rỗng
        d = self.run_case(ev)
        self.assertEqual(d["decision"], "BLOCKED")
        self.assertTrue({"SIG-001", "SIG-002", "SIG-003"} <= self.violation_ids(d))
        self.assertFalse(any(i.startswith(("VULN", "PROV", "SBOM")) for i in self.violation_ids(d)))

    def test_04_missing_provenance_is_blocked(self):
        ev = fx.valid_evidence()
        ev["verification.json"].update(skip_provenance=True, provenance_verification="failure")
        ev["provenance-verify.json"] = ""
        d = self.run_case(ev)
        self.assertEqual(d["decision"], "BLOCKED")
        self.assertEqual(self.violation_ids(d), {"PROV-001", "PROV-002"})

    # ---------------------------------------------------- tấn công / giả mạo evidence
    def test_signature_from_other_branch_is_blocked(self):
        ev = fx.valid_evidence()
        ev["signature-verify.json"] = fx.signature(subject=fx.SUBJECT.replace("refs/heads/main", "refs/heads/evil"))
        self.assertIn("SIG-003", self.violation_ids(self.run_case(ev)))

    def test_signature_from_other_repo_is_blocked(self):
        ev = fx.valid_evidence()
        ev["signature-verify.json"] = fx.signature(subject=fx.SUBJECT.replace("wnhhuong/", "attacker/"))
        self.assertIn("SIG-003", self.violation_ids(self.run_case(ev)))

    def test_signature_for_other_digest_is_blocked(self):
        ev = fx.valid_evidence()
        ev["signature-verify.json"] = fx.signature(digest=fx.OTHER_DIGEST)
        self.assertIn("SIG-002", self.violation_ids(self.run_case(ev)))

    def test_tampered_uploaded_sbom_is_blocked(self):
        ev = fx.valid_evidence()
        ev["sbom.cdx.json"]["components"] = ev["sbom.cdx.json"]["components"][:12]
        self.assertIn("SBOM-004", self.violation_ids(self.run_case(ev)))

    def test_tampered_uploaded_vuln_report_is_blocked(self):
        ev = fx.valid_evidence()
        signed = fx.vuln(["CRITICAL"])
        ev["vuln-verify.json"] = fx.dsse("https://cosign.sigstore.dev/attestation/vuln/v1", signed)
        ev["vuln.cosign.json"] = fx.vuln([])  # kẻ tấn công xóa lỗ hổng khỏi bản upload
        d = self.run_case(ev)
        self.assertTrue({"VULN-002", "VULN-003"} <= self.violation_ids(d))

    def test_vuln_report_of_other_image_is_blocked(self):
        ev = fx.valid_evidence()
        ev["vuln-verify.json"] = None
        ev["verification.json"]["vuln_verification"] = "failure"
        ev["vuln.cosign.json"] = fx.vuln([], digest=fx.OTHER_DIGEST)
        self.assertIn("VULN-001", self.violation_ids(self.run_case(ev)))

    def test_sbom_attestation_for_other_digest_is_blocked(self):
        ev = fx.valid_evidence()
        ev["sbom-verify.json"] = fx.dsse("https://cyclonedx.org/bom", fx.sbom(fx.OTHER_DIGEST), fx.OTHER_DIGEST)
        self.assertIn("SBOM-002", self.violation_ids(self.run_case(ev)))

    def test_provenance_wrong_ref_is_blocked(self):
        ev = fx.valid_evidence()
        ev["provenance-verify.json"] = fx.provenance(ref="refs/heads/dev")
        self.assertIn("PROV-002", self.violation_ids(self.run_case(ev)))

    def test_provenance_self_hosted_runner_is_blocked(self):
        ev = fx.valid_evidence()
        ev["provenance-verify.json"] = fx.provenance(runner="self-hosted")
        self.assertIn("PROV-002", self.violation_ids(self.run_case(ev)))

    def test_commit_mismatch_is_blocked(self):
        ev = fx.valid_evidence()
        ev["provenance-verify.json"] = fx.provenance(commit="d" * 40)
        self.assertIn("CONS-001", self.violation_ids(self.run_case(ev)))

    def test_leaked_secret_is_blocked(self):
        ev = fx.valid_evidence()
        ev["gitleaks.json"] = [{"RuleID": "github-pat", "File": "app/x.properties"}]
        self.assertEqual(self.violation_ids(self.run_case(ev)), {"SEC-001"})

    def test_missing_evidence_file_is_blocked(self):
        ev = fx.valid_evidence()
        ev["sbom.cdx.json"] = None
        d = self.run_case(ev)
        self.assertIn("EVD-001", self.violation_ids(d))

    def test_invalid_json_is_blocked(self):
        ev = fx.valid_evidence()
        ev["gitleaks.json"] = "{not json"
        self.assertIn("EVD-001", self.violation_ids(self.run_case(ev)))

    # ---------------------------------------------------- policy
    def test_active_exception_suppresses_vulnerability(self):
        ev = fx.valid_evidence()
        v = fx.vuln(["HIGH"])
        ev["vuln-verify.json"] = fx.dsse("https://cosign.sigstore.dev/attestation/vuln/v1", v)
        ev["vuln.cosign.json"] = v
        pol = copy.deepcopy(self.policy)
        pol["rules"]["vulnerabilities"]["exceptions"] = [
            {"id": "CVE-2026-1000", "reason": "not reachable", "expires": "2026-12-31"}]
        self.assertEqual(self.run_case(ev, pol)["decision"], "ALLOWED")
        pol["rules"]["vulnerabilities"]["exceptions"][0]["expires"] = "2026-10-01"  # hết hạn
        self.assertEqual(self.run_case(ev, pol)["decision"], "BLOCKED")

    def test_sast_is_warning_in_default_but_blocks_in_strict(self):
        ev = fx.valid_evidence()
        ev["semgrep.json"]["results"] = [{"check_id": "x.missing-user", "path": "Dockerfile",
                                          "start": {"line": 1}, "extra": {"severity": "ERROR"}}]
        d = self.run_case(ev)
        self.assertEqual(d["decision"], "ALLOWED")
        self.assertIn("SAST-001", {w["id"] for w in d["warnings"]})
        strict = load_policy(POLICY_DIR / "strict.yaml")
        self.assertIn("SAST-001", self.violation_ids(self.run_case(ev, strict)))

    def test_stale_report_only_warns_in_default(self):
        ev = fx.valid_evidence()
        v = fx.vuln([], created="2026-09-01T00:00:00Z")
        ev["vuln-verify.json"] = fx.dsse("https://cosign.sigstore.dev/attestation/vuln/v1", v)
        ev["vuln.cosign.json"] = v
        d = self.run_case(ev)
        self.assertEqual(d["decision"], "ALLOWED")
        self.assertIn("VULN-004", {w["id"] for w in d["warnings"]})

    def test_invalid_policy_is_rejected(self):
        bad = self.root / "bad.yaml"
        bad.write_text("kind: SecurityPolicy\nidentity: {repository: a/b}\nrules: {secrets: {action: maybe}}\n")
        with self.assertRaises(PolicyError):
            load_policy(bad)

    # ---------------------------------------------------- CLI
    def cli(self, *args: str) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(list(args))

    def test_cli_exit_codes(self):
        fx.write(fx.valid_evidence(), self.root / "ok")
        bad = fx.valid_evidence()
        bad["gitleaks.json"] = [{"RuleID": "aws"}]
        fx.write(bad, self.root / "bad")
        pol = str(POLICY_DIR / "default.yaml")
        out = str(self.root / "d.json")
        common = ["--policy", pol, "--now", fx.NOW, "--out", out]
        self.assertEqual(self.cli("evaluate", "--evidence", str(self.root / "ok"), *common), 0)
        self.assertEqual(json.loads(Path(out).read_text())["decision"], "ALLOWED")
        self.assertEqual(self.cli("evaluate", "--evidence", str(self.root / "bad"), *common), 1)
        self.assertEqual(self.cli("evaluate", "--evidence", str(self.root / "nope"), *common), 2)

if __name__ == "__main__":
    unittest.main()
