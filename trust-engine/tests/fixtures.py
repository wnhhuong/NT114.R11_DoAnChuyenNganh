"""Sinh bộ evidence tổng hợp (synthetic) có cấu trúc giống hệt output thật của secure-ci.yml.

valid_evidence() trả về dict {tên file: nội dung}; mỗi test sửa đúng một chỗ để tạo kịch bản.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

REPO = "wnhhuong/NT114.R11_DoAnChuyenNganh"
IMAGE = "ghcr.io/wnhhuong/nt114.r11_doanchuyennganh"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
COMMIT = "c" * 40
NOW = "2026-10-19T03:00:00Z"
SCAN_TIME = "2026-10-19T02:00:00.123456789Z"
SUBJECT = f"https://github.com/{REPO}/.github/workflows/secure-ci.yml@refs/heads/main"


def dsse(predicate_type: str, predicate: dict, digest: str = DIGEST) -> dict:
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": predicate_type,
        "subject": [{"name": IMAGE, "digest": {"sha256": digest.split(":")[1]}}],
        "predicate": predicate,
    }
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        "signatures": [{"keyid": "", "sig": "MEUC..."}],
    }


def sbom(digest: str = DIGEST) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"component": {"type": "container", "name": IMAGE, "version": digest}},
        "components": [{"type": "library", "name": f"lib{i}", "version": "1.0"} for i in range(20)],
    }


def vuln(severities: list[str], digest: str = DIGEST, created: str = SCAN_TIME) -> dict:
    vulns = [{"VulnerabilityID": f"CVE-2026-{1000 + i}", "PkgName": "pkg", "InstalledVersion": "1",
              "FixedVersion": "2", "Status": "fixed", "Severity": s} for i, s in enumerate(severities)]
    return {
        "invocation": {}, "metadata": {},
        "scanner": {"uri": "pkg:github/aquasecurity/trivy@0.70.0", "version": "0.70.0", "result": {
            "SchemaVersion": 2, "CreatedAt": created,
            "ArtifactName": f"{IMAGE}@{digest}", "ArtifactType": "container_image",
            "Metadata": {"RepoDigests": [f"{IMAGE}@{digest}"]},
            "Results": [{"Target": "Java", "Class": "lang-pkgs", "Vulnerabilities": vulns}],
        }},
    }


def signature(subject: str = SUBJECT, digest: str = DIGEST, trigger: str = "push",
              commit: str = COMMIT) -> list:
    return [{
        "critical": {"identity": {"docker-reference": IMAGE},
                     "image": {"docker-manifest-digest": digest},
                     "type": "cosign container image signature"},
        "optional": {"Issuer": "https://token.actions.githubusercontent.com", "Subject": subject,
                     "githubWorkflowRepository": REPO, "githubWorkflowRef": "refs/heads/main",
                     "githubWorkflowSha": commit, "githubWorkflowTrigger": trigger},
    }]


def provenance(ref: str = "refs/heads/main", runner: str = "github-hosted",
               commit: str = COMMIT, digest: str = DIGEST) -> list:
    return [{
        "attestation": {"bundle": {}},
        "verificationResult": {
            "signature": {"certificate": {"runnerEnvironment": runner,
                                          "sourceRepositoryDigest": commit}},
            "statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": IMAGE, "digest": {"sha256": digest.split(":")[1]}}],
                "predicate": {
                    "buildDefinition": {
                        "externalParameters": {"workflow": {
                            "repository": f"https://github.com/{REPO}",
                            "path": ".github/workflows/secure-ci.yml", "ref": ref}},
                        "resolvedDependencies": [{"uri": f"git+https://github.com/{REPO}@{ref}",
                                                  "digest": {"gitCommit": commit}}],
                    },
                    "runDetails": {"builder": {"id": f"https://github.com/actions/runner/{runner}"}},
                },
            },
        },
    }]


def valid_evidence() -> dict:
    v = vuln(["MEDIUM"])
    s = sbom()
    return {
        "verification.json": {
            "image": IMAGE, "digest": DIGEST, "commit": COMMIT, "ref": "refs/heads/main",
            "skip_sign": False, "skip_provenance": False,
            "signature_verification": "success", "sbom_verification": "success",
            "vuln_verification": "success", "provenance_verification": "success",
        },
        "signature-verify.json": signature(),
        "sbom-verify.json": dsse("https://cyclonedx.org/bom", s),
        "vuln-verify.json": dsse("https://cosign.sigstore.dev/attestation/vuln/v1", v),
        "provenance-verify.json": provenance(),
        "sbom.cdx.json": copy.deepcopy(s),
        "vuln.cosign.json": copy.deepcopy(v),
        "semgrep.json": {"version": "1.179.0", "results": [], "errors": []},
        "gitleaks.json": [],
        "trivy-deps.json": {"SchemaVersion": 2, "Metadata": {"Commit": COMMIT},
                            "Results": [{"Target": "app/gradle.lockfile", "Vulnerabilities": []}]},
    }


def write(evidence: dict, root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, content in evidence.items():
        if content is None:
            continue  # None = file không tồn tại
        text = content if isinstance(content, str) else json.dumps(content)
        (root / name).write_text(text, encoding="utf-8")
    return root
