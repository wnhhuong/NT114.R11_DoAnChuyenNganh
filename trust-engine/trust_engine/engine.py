"""Trust Evaluation Engine: chạy các rule theo policy và tổng hợp quyết định."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from . import __version__
from .evidence import EvidenceBundle, decode_dsse_statements, pick_statement, statement_digests, PREDICATE_CYCLONEDX
from .rules import FAIL, PASS, RULES, SKIP, Context, RuleResult

ALLOWED, BLOCKED = "ALLOWED", "BLOCKED"
TRUSTED, UNTRUSTED = "TRUSTED", "UNTRUSTED"


def _resolve_artifact(ev: EvidenceBundle, image: str | None, digest: str | None):
    ver = ev.data("verification") or {}
    if digest:
        d_src = "cli"
    elif isinstance(ver, dict) and ver.get("digest"):
        digest, d_src = ver["digest"], "verification.json"
    else:
        # Fallback cho evidence cũ: lấy từ subject của SBOM attestation (đã ký)
        st = pick_statement(decode_dsse_statements(ev.data("sbom_attestation")), PREDICATE_CYCLONEDX, None)
        ds = statement_digests(st)
        if ds:
            digest, d_src = ds[0], "sbom-attestation-subject"
        else:
            vr = ev.data("vuln_report") or {}
            name = str(((vr.get("scanner") or {}).get("result") or {}).get("ArtifactName", ""))
            digest, d_src = (name.split("@", 1)[1], "vuln-report(unsigned)") if "@" in name else (None, "none")
    if digest and not digest.startswith("sha256:"):
        digest = "sha256:" + digest

    if not image:
        image = ver.get("image") if isinstance(ver, dict) else None
    if not image:
        sbom = ev.data("sbom") or {}
        image = ((sbom.get("metadata") or {}).get("component") or {}).get("name")
    if not image:
        vr = ev.data("vuln_report") or {}
        name = str(((vr.get("scanner") or {}).get("result") or {}).get("ArtifactName", ""))
        image = name.split("@", 1)[0] or None
    return (image.lower() if image else None), digest, d_src


def _severity_for(result: RuleResult, policy: dict) -> str:
    if result.severity:
        return result.severity
    if result.category == "evidence":
        return policy["evidence"]["action"]
    return policy["rules"][result.category]["action"]


def _score(results: list[RuleResult], weights: dict) -> int:
    total = 0.0
    for cat, weight in weights.items():
        rs = [r for r in results if r.category == cat and r.status == FAIL]
        if any(r.severity == "block" for r in rs):
            continue
        total += weight * (0.5 if rs else 1.0)
    return round(total * 100 / (sum(weights.values()) or 1))


def evaluate(policy: dict, ev: EvidenceBundle, image: str | None = None,
             digest: str | None = None, now: datetime | None = None) -> dict:
    t0 = time.perf_counter()
    now = now or datetime.now(timezone.utc)
    image, digest, d_src = _resolve_artifact(ev, image, digest)
    ctx = Context(policy=policy, ev=ev, image=image, digest=digest, digest_source=d_src, now=now)

    results: list[RuleResult] = []
    for category, fn in RULES:
        action = policy["evidence"]["action"] if category == "evidence" else policy["rules"][category]["action"]
        if action == "off":
            continue
        for r in fn(ctx):
            r.severity = _severity_for(r, policy) if r.status == FAIL else None
            if r.status == FAIL and r.severity == "off":
                r.status, r.severity = SKIP, None
            results.append(r)

    violations = [r for r in results if r.status == FAIL and r.severity == "block"]
    warnings = [r for r in results if r.status == FAIL and r.severity == "warn"]
    decision = BLOCKED if violations else ALLOWED

    return {
        "schema": "trust-decision/v1",
        "engine_version": __version__,
        "evaluated_at": now.isoformat().replace("+00:00", "Z"),
        "artifact": {"image": image, "digest": digest, "digest_source": d_src},
        "policy": {
            "name": policy.get("metadata", {}).get("name"),
            "version": policy.get("metadata", {}).get("version"),
            "sha256": policy.get("_source", {}).get("sha256"),
        },
        "decision": decision,
        "trust_level": TRUSTED if decision == ALLOWED else UNTRUSTED,
        "trust_score": _score(results, policy["scoring"]["weights"]),
        "summary": {
            "rules": len(results),
            "passed": sum(r.status == PASS for r in results),
            "violations": len(violations),
            "warnings": len(warnings),
            "skipped": sum(r.status == SKIP for r in results),
        },
        "violations": [r.to_dict() for r in violations],
        "warnings": [r.to_dict() for r in warnings],
        "rules": [r.to_dict() for r in results],
        "evidence": {name: item.to_dict() for name, item in ev.items.items()},
        "notes": ev.notes,
        "evaluation_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
