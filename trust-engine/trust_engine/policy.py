"""Nạp Security Policy (YAML) và điền giá trị mặc định."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import yaml

VALID_ACTIONS = {"block", "warn", "off"}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

DEFAULTS: dict[str, Any] = {
    "identity": {
        "repository": "",
        "workflow_path": ".github/workflows/secure-ci.yml",
        "allowed_refs": ["refs/heads/main"],
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "allowed_triggers": ["push", "workflow_dispatch"],
    },
    "evidence": {
        "action": "block",
        "required": ["verification", "signature", "sbom_attestation", "sbom",
                     "vuln_report", "semgrep", "gitleaks", "trivy_deps"],
    },
    "rules": {
        "signature": {"action": "block"},
        "sbom": {"action": "block", "min_components": 10, "uploaded_mismatch_action": "block"},
        "provenance": {"action": "block", "missing_detail_action": "warn",
                       "require_github_hosted": True},
        "vulnerabilities": {
            "action": "block",
            "max": {"CRITICAL": 0, "HIGH": 0},
            "warn_above": {"MEDIUM": 0, "UNKNOWN": 0},
            "ignore_unfixed": False,
            "signed_report_action": "warn",
            "uploaded_mismatch_action": "block",
            "max_age_days": 7,
            "freshness_action": "warn",
            "exceptions": [],
        },
        "dependencies": {"action": "block", "max": {"CRITICAL": 0, "HIGH": 0},
                         "coverage_action": "warn"},
        "secrets": {"action": "block", "max_findings": 0},
        "sast": {"action": "warn", "max": {"ERROR": 0}},
        "consistency": {"action": "block"},
    },
    "scoring": {
        "weights": {"signature": 25, "provenance": 25, "sbom": 15,
                    "vulnerabilities": 25, "secrets": 10},
    },
}


class PolicyError(ValueError):
    pass


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _check_action(path: str, value: Any) -> None:
    if value not in VALID_ACTIONS:
        raise PolicyError(f"{path} phải là một trong {sorted(VALID_ACTIONS)}, nhận '{value}'")


def validate(policy: dict) -> None:
    if policy.get("kind") != "SecurityPolicy":
        raise PolicyError("kind phải là 'SecurityPolicy'")
    if not policy["identity"].get("repository"):
        raise PolicyError("identity.repository là bắt buộc")
    _check_action("evidence.action", policy["evidence"]["action"])
    for rule, cfg in policy["rules"].items():
        for key, value in cfg.items():
            if key == "action" or key.endswith("_action"):
                _check_action(f"rules.{rule}.{key}", value)
    for sev in policy["rules"]["vulnerabilities"]["max"]:
        if sev not in SEVERITIES:
            raise PolicyError(f"Severity không hợp lệ: {sev}")
    for exc in policy["rules"]["vulnerabilities"]["exceptions"]:
        if not exc.get("id") or not exc.get("reason") or not exc.get("expires"):
            raise PolicyError("Mỗi exception cần id, reason, expires")


def load_policy(path: str | Path) -> dict:
    raw = Path(path).read_bytes()
    doc = yaml.safe_load(raw) or {}
    policy = _merge(DEFAULTS, doc)
    validate(policy)
    policy["_source"] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
    return policy
