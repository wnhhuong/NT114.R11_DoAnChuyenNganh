"""Các rule của Security Policy.

Mỗi rule nhận Context, trả về RuleResult với status:
  pass  - đạt
  fail  - vi phạm (mức độ do policy quyết định: block | warn)
  skip  - không áp dụng được / bị tắt
Nguyên tắc fail-closed: thiếu hoặc hỏng evidence => fail, không bao giờ pass.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable

from .evidence import (
    PREDICATE_CYCLONEDX,
    PREDICATE_SLSA_PREFIX,
    PREDICATE_VULN,
    EvidenceBundle,
    as_list,
    canonical,
    decode_dsse_statements,
    pick_statement,
    provenance_entries,
    statement_digests,
)

PASS, FAIL, SKIP = "pass", "fail", "skip"


@dataclass
class RuleResult:
    id: str
    category: str
    title: str
    status: str
    message: str
    details: dict = field(default_factory=dict)
    severity: str | None = None  # block | warn | off — do engine điền / rule override

    def to_dict(self) -> dict:
        return {
            "id": self.id, "category": self.category, "title": self.title,
            "status": self.status, "severity": self.severity,
            "message": self.message, "details": self.details,
        }


@dataclass
class Context:
    policy: dict
    ev: EvidenceBundle
    image: str | None
    digest: str | None
    digest_source: str
    now: datetime
    cache: dict = field(default_factory=dict)

    def rule_cfg(self, name: str) -> dict:
        return self.policy["rules"][name]

    @property
    def verification(self) -> dict:
        data = self.ev.data("verification")
        return data if isinstance(data, dict) else {}

    # --- statement đã giải mã (có chữ ký) -------------------------------------
    def sbom_statement(self) -> dict | None:
        if "sbom_st" not in self.cache:
            sts = decode_dsse_statements(self.ev.data("sbom_attestation"))
            self.cache["sbom_st"] = pick_statement(sts, PREDICATE_CYCLONEDX, self.digest)
        return self.cache["sbom_st"]

    def vuln_statement(self) -> dict | None:
        if "vuln_st" not in self.cache:
            sts = decode_dsse_statements(self.ev.data("vuln_attestation"))
            self.cache["vuln_st"] = pick_statement(sts, PREDICATE_VULN, self.digest)
        return self.cache["vuln_st"]

    def vuln_source(self) -> tuple[dict | None, str]:
        """Ưu tiên báo cáo lỗ hổng đã ký (attestation); fallback bản upload."""
        st = self.vuln_statement()
        if st and isinstance(st.get("predicate"), dict):
            return st["predicate"], "signed-attestation"
        data = self.ev.data("vuln_report")
        if isinstance(data, dict):
            return data, "uploaded-artifact(unsigned)"
        return None, "none"


def _r(rid: str, cat: str, title: str, status: str, msg: str, **details: Any) -> RuleResult:
    return RuleResult(rid, cat, title, status, msg, details)


def _bare(digest: str | None) -> str:
    return (digest or "").split(":", 1)[-1]


def _verify_ok(ctx: Context, key: str) -> bool:
    return str(ctx.verification.get(key, "")).lower() == "success"


# =============================================================== EVIDENCE

def rule_evidence_required(ctx: Context) -> list[RuleResult]:
    required = ctx.policy["evidence"]["required"]
    missing = [n for n in required if ctx.ev.get(n).status == "missing"]
    invalid = [n for n in required if ctx.ev.get(n).status == "invalid"]
    if missing or invalid:
        return [_r("EVD-001", "evidence", "Đủ evidence bắt buộc", FAIL,
                   f"Thiếu: {missing or '-'}; hỏng: {invalid or '-'}",
                   missing=missing, invalid=invalid)]
    return [_r("EVD-001", "evidence", "Đủ evidence bắt buộc", PASS,
               f"Có đủ {len(required)} evidence bắt buộc")]


def rule_digest_known(ctx: Context) -> list[RuleResult]:
    if ctx.digest_source in ("cli", "verification.json"):
        return [_r("EVD-002", "evidence", "Xác định digest cần đánh giá", PASS,
                   f"Digest lấy từ {ctx.digest_source}", digest=ctx.digest)]
    if ctx.digest:
        r = _r("EVD-002", "evidence", "Xác định digest cần đánh giá", FAIL,
               f"Không có digest tin cậy (CLI/verification.json); suy ra từ {ctx.digest_source}",
               digest=ctx.digest)
        r.severity = "warn"
        return [r]
    return [_r("EVD-002", "evidence", "Xác định digest cần đánh giá", FAIL,
               "Không xác định được digest của image => không thể ràng buộc evidence với artifact")]


# =============================================================== SIGNATURE

def rule_signature(ctx: Context) -> list[RuleResult]:
    out = []
    pol = ctx.policy["identity"]
    cat = "signature"

    ok = _verify_ok(ctx, "signature_verification")
    out.append(_r("SIG-001", cat, "Chữ ký image xác minh thành công", PASS if ok else FAIL,
                  "cosign verify: success" if ok else
                  f"cosign verify: {ctx.verification.get('signature_verification', 'không có kết quả')}",
                  skip_sign=ctx.verification.get("skip_sign")))

    sigs = [s for s in as_list(ctx.ev.data("signature")) if isinstance(s, dict)]
    if not sigs:
        out.append(_r("SIG-002", cat, "Chữ ký gắn với đúng digest/image", FAIL,
                      "signature-verify.json rỗng hoặc không có => không có chữ ký để đối chiếu"))
        out.append(_r("SIG-003", cat, "Danh tính người ký đúng workflow tin cậy", FAIL,
                      "Không có certificate để kiểm tra danh tính"))
        return out

    bare = _bare(ctx.digest)
    bound = [s for s in sigs
             if ((s.get("critical") or {}).get("image") or {}).get("docker-manifest-digest", "")
             .split(":", 1)[-1] == bare]
    ref_ok = True
    if ctx.image:
        refs = {((s.get("critical") or {}).get("identity") or {}).get("docker-reference", "").lower()
                for s in bound}
        ref_ok = ctx.image.lower() in refs
    out.append(_r("SIG-002", cat, "Chữ ký gắn với đúng digest/image",
                  PASS if bound and ref_ok else FAIL,
                  f"{len(bound)}/{len(sigs)} chữ ký trỏ tới digest {ctx.digest}" +
                  ("" if ref_ok else f"; docker-reference không khớp {ctx.image}")))

    repo = pol["repository"].lower()
    expected_subjects = {f"https://github.com/{repo}/{pol['workflow_path']}@{ref}".lower()
                         for ref in pol["allowed_refs"]}
    matched, seen = None, []
    for s in bound:
        opt = s.get("optional") or {}
        subject = str(opt.get("Subject", "")).lower()
        issuer = opt.get("Issuer") or opt.get("1.3.6.1.4.1.57264.1.1")
        trigger = opt.get("githubWorkflowTrigger") or opt.get("1.3.6.1.4.1.57264.1.2")
        seen.append({"subject": opt.get("Subject"), "issuer": issuer, "trigger": trigger})
        if subject in expected_subjects and issuer == pol["oidc_issuer"] \
                and trigger in pol["allowed_triggers"]:
            matched = opt
            break
    if matched:
        ctx.cache["signer_commit"] = matched.get("githubWorkflowSha") or matched.get("1.3.6.1.4.1.57264.1.3")
        out.append(_r("SIG-003", cat, "Danh tính người ký đúng workflow tin cậy", PASS,
                      f"Ký bởi {matched.get('Subject')} ({matched.get('githubWorkflowTrigger')})",
                      commit=ctx.cache["signer_commit"]))
    else:
        out.append(_r("SIG-003", cat, "Danh tính người ký đúng workflow tin cậy", FAIL,
                      "Không có chữ ký nào khớp repository/workflow/ref/issuer/trigger trong policy",
                      expected=sorted(expected_subjects), seen=seen))
    return out


# =============================================================== SBOM

def rule_sbom(ctx: Context) -> list[RuleResult]:
    cfg, cat, out = ctx.rule_cfg("sbom"), "sbom", []

    ok = _verify_ok(ctx, "sbom_verification")
    out.append(_r("SBOM-001", cat, "SBOM attestation xác minh thành công", PASS if ok else FAIL,
                  f"cosign verify-attestation --type cyclonedx: {ctx.verification.get('sbom_verification', 'không có')}"))

    st = ctx.sbom_statement()
    if not st:
        out.append(_r("SBOM-002", cat, "SBOM attestation gắn với đúng digest", FAIL,
                      "Không giải mã được attestation CycloneDX nào từ sbom-verify.json"))
        out.append(_r("SBOM-003", cat, "Nội dung SBOM hợp lệ", FAIL, "Không có SBOM đã ký"))
        return out

    digests = statement_digests(st)
    bound = any(_bare(d) == _bare(ctx.digest) for d in digests)
    out.append(_r("SBOM-002", cat, "SBOM attestation gắn với đúng digest", PASS if bound else FAIL,
                  f"subject={digests}", expected=ctx.digest))

    bom = st.get("predicate") or {}
    comps = bom.get("components") or []
    meta_ver = ((bom.get("metadata") or {}).get("component") or {}).get("version", "")
    problems = []
    if bom.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat khác CycloneDX")
    if len(comps) < cfg["min_components"]:
        problems.append(f"chỉ {len(comps)} component (< {cfg['min_components']})")
    if ctx.digest and meta_ver and _bare(meta_ver) != _bare(ctx.digest):
        problems.append(f"metadata.component.version={meta_ver} khác digest")
    out.append(_r("SBOM-003", cat, "Nội dung SBOM hợp lệ", FAIL if problems else PASS,
                  "; ".join(problems) or f"CycloneDX {bom.get('specVersion')}, {len(comps)} components",
                  components=len(comps), spec=bom.get("specVersion")))

    uploaded = ctx.ev.data("sbom")
    if uploaded is None:
        r = _r("SBOM-004", cat, "SBOM upload trùng SBOM đã ký", FAIL,
               "Không có sbom.cdx.json để đối chiếu")
        r.severity = "warn"
    elif canonical(uploaded) == canonical(bom):
        r = _r("SBOM-004", cat, "SBOM upload trùng SBOM đã ký", PASS,
               "sbom.cdx.json giống hệt predicate đã ký")
    else:
        r = _r("SBOM-004", cat, "SBOM upload trùng SBOM đã ký", FAIL,
               "sbom.cdx.json KHÁC predicate đã ký => evidence có thể bị sửa sau khi ký")
        r.severity = cfg["uploaded_mismatch_action"]
    out.append(r)
    return out


# =============================================================== PROVENANCE

def rule_provenance(ctx: Context) -> list[RuleResult]:
    cfg, pol, cat, out = ctx.rule_cfg("provenance"), ctx.policy["identity"], "provenance", []

    ok = _verify_ok(ctx, "provenance_verification")
    out.append(_r("PROV-001", cat, "Build provenance xác minh thành công", PASS if ok else FAIL,
                  f"gh attestation verify: {ctx.verification.get('provenance_verification', 'không có')}",
                  skip_provenance=ctx.verification.get("skip_provenance")))

    entries = provenance_entries(ctx.ev.data("provenance"))
    entries = [e for e in entries
               if str(e["statement"].get("predicateType", "")).startswith(PREDICATE_SLSA_PREFIX)]
    if not entries:
        r = _r("PROV-002", cat, "Nội dung provenance khớp policy", FAIL,
               "Không có provenance-verify.json (JSON) => chỉ dựa vào trạng thái PROV-001")
        r.severity = cfg["missing_detail_action"] if ok else cfg["action"]
        out.append(r)
        return out

    entry = next((e for e in entries
                  if any(_bare(d) == _bare(ctx.digest) for d in statement_digests(e["statement"]))),
                 None)
    if entry is None:
        out.append(_r("PROV-002", cat, "Nội dung provenance khớp policy", FAIL,
                      "Không có provenance nào có subject trùng digest"))
        return out

    pred = entry["statement"].get("predicate") or {}
    wf = ((pred.get("buildDefinition") or {}).get("externalParameters") or {}).get("workflow") or {}
    deps = (pred.get("buildDefinition") or {}).get("resolvedDependencies") or []
    builder = ((pred.get("runDetails") or {}).get("builder") or {}).get("id", "")
    cert = entry["certificate"]
    runner_env = cert.get("runnerEnvironment") or ("github-hosted" if "github-hosted" in builder else "")
    commit = next(((d.get("digest") or {}).get("gitCommit") for d in deps
                   if (d.get("digest") or {}).get("gitCommit")), None) \
        or cert.get("sourceRepositoryDigest")
    ctx.cache["provenance_commit"] = commit

    problems = []
    if str(wf.get("repository", "")).lower() != f"https://github.com/{pol['repository']}".lower():
        problems.append(f"repository={wf.get('repository')}")
    if wf.get("path") != pol["workflow_path"]:
        problems.append(f"workflow path={wf.get('path')}")
    if wf.get("ref") not in pol["allowed_refs"]:
        problems.append(f"ref={wf.get('ref')}")
    if cfg["require_github_hosted"] and runner_env != "github-hosted":
        problems.append(f"runner={runner_env or builder or 'không rõ'}")
    out.append(_r("PROV-002", cat, "Nội dung provenance khớp policy", FAIL if problems else PASS,
                  "; ".join(problems) or f"{wf.get('repository')} {wf.get('path')}@{wf.get('ref')}",
                  builder=builder, commit=commit))
    return out


# =============================================================== VULNERABILITIES

def _active_exceptions(cfg: dict, today: date) -> tuple[dict, list]:
    active, expired = {}, []
    for exc in cfg.get("exceptions") or []:
        exp = exc["expires"]
        if not isinstance(exp, date):
            exp = date.fromisoformat(str(exp))
        if exp >= today:
            active[exc["id"]] = exc
        else:
            expired.append(exc["id"])  # exception hết hạn => lỗ hổng tính lại bình thường
    return active, expired


def _count_vulns(report: dict, cfg: dict, exceptions: dict) -> tuple[Counter, list, list]:
    counts, suppressed, top = Counter(), [], []
    results = (report.get("scanner") or {}).get("result", report).get("Results") or []
    for res in results:
        for v in res.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID")
            if cfg.get("ignore_unfixed") and v.get("Status") != "fixed":
                suppressed.append({"id": vid, "why": "unfixed"})
                continue
            if vid in exceptions:
                suppressed.append({"id": vid, "why": exceptions[vid]["reason"]})
                continue
            sev = (v.get("Severity") or "UNKNOWN").upper()
            counts[sev] += 1
            if sev in ("CRITICAL", "HIGH"):
                top.append(f"{sev} {vid} {v.get('PkgName')} {v.get('InstalledVersion')} -> {v.get('FixedVersion')}")
    return counts, suppressed, top


def _threshold_problems(counts: Counter, limits: dict) -> list[str]:
    return [f"{sev}={counts.get(sev, 0)} > {lim}" for sev, lim in limits.items()
            if lim is not None and lim >= 0 and counts.get(sev, 0) > lim]


def rule_vulnerabilities(ctx: Context) -> list[RuleResult]:
    cfg, cat, out = ctx.rule_cfg("vulnerabilities"), "vulnerabilities", []
    report, source = ctx.vuln_source()
    if report is None:
        out.append(_r("VULN-001", cat, "Báo cáo lỗ hổng gắn với đúng image", FAIL,
                      "Không có báo cáo lỗ hổng image"))
        out.append(_r("VULN-002", cat, "Lỗ hổng trong ngưỡng cho phép", FAIL,
                      "Không có dữ liệu => fail-closed"))
        return out

    result = (report.get("scanner") or {}).get("result") or report
    name = str(result.get("ArtifactName", ""))
    repo_digests = (result.get("Metadata") or {}).get("RepoDigests") or []
    bound = bool(ctx.digest) and (_bare(ctx.digest) in name or any(_bare(ctx.digest) in d for d in repo_digests))
    out.append(_r("VULN-001", cat, "Báo cáo lỗ hổng gắn với đúng image", PASS if bound else FAIL,
                  f"ArtifactName={name}", source=source))

    active, expired = _active_exceptions(cfg, ctx.now.date())
    counts, suppressed, top = _count_vulns(report, cfg, active)
    problems = _threshold_problems(counts, cfg["max"])
    out.append(_r("VULN-002", cat, "Lỗ hổng trong ngưỡng cho phép", FAIL if problems else PASS,
                  "; ".join(problems) or f"Đạt ngưỡng {cfg['max']}",
                  counts=dict(counts), suppressed=suppressed, expired_exceptions=expired,
                  top_findings=top[:20], source=source))

    # VULN-003: báo cáo có được ký và có khớp bản upload không
    signed = source == "signed-attestation" and _verify_ok(ctx, "vuln_verification")
    uploaded = ctx.ev.data("vuln_report")
    # So sánh phần báo cáo Trivy (scanner.result); phần vỏ predicate do cosign tự serialize lại
    up_result = ((uploaded or {}).get("scanner") or {}).get("result") if isinstance(uploaded, dict) else None
    if signed and up_result is not None and canonical(up_result) != canonical(result):
        r = _r("VULN-003", cat, "Báo cáo lỗ hổng có chữ ký và toàn vẹn", FAIL,
               "vuln.cosign.json KHÁC predicate đã ký => evidence bị sửa")
        r.severity = cfg["uploaded_mismatch_action"]
    elif signed:
        r = _r("VULN-003", cat, "Báo cáo lỗ hổng có chữ ký và toàn vẹn", PASS,
               "Dùng predicate từ attestation --type vuln đã verify")
    else:
        r = _r("VULN-003", cat, "Báo cáo lỗ hổng có chữ ký và toàn vẹn", FAIL,
               "Báo cáo lỗ hổng chưa được verify chữ ký; đang dùng bản upload")
        r.severity = cfg["signed_report_action"]
    out.append(r)

    created = result.get("CreatedAt")
    if created:
        ts = datetime.fromisoformat(re.sub(r"\.(\d{6})\d*", r".\1", created).replace("Z", "+00:00"))
        age = (ctx.now - ts).total_seconds() / 86400
        stale = age > cfg["max_age_days"]
        r = _r("VULN-004", cat, "Báo cáo lỗ hổng còn mới", FAIL if stale else PASS,
               f"Quét lúc {created} ({age:.1f} ngày trước, tối đa {cfg['max_age_days']})")
    else:
        r = _r("VULN-004", cat, "Báo cáo lỗ hổng còn mới", FAIL, "Không có CreatedAt")
    r.severity = cfg["freshness_action"]
    out.append(r)

    warn_problems = _threshold_problems(counts, cfg.get("warn_above") or {})
    r = _r("VULN-005", cat, "Lỗ hổng mức thấp hơn (cảnh báo)", FAIL if warn_problems else PASS,
           "; ".join(warn_problems) or "Không vượt ngưỡng cảnh báo", counts=dict(counts))
    r.severity = "warn"
    out.append(r)
    return out


# =============================================================== DEPENDENCIES

def rule_dependencies(ctx: Context) -> list[RuleResult]:
    cfg, cat, out = ctx.rule_cfg("dependencies"), "dependencies", []
    report = ctx.ev.data("trivy_deps")
    if not isinstance(report, dict):
        out.append(_r("DEP-001", cat, "Dependency trong ngưỡng cho phép", FAIL, "Không có trivy-deps.json"))
        return out
    counts, _, top = _count_vulns(report, {"ignore_unfixed": False}, {})
    problems = _threshold_problems(counts, cfg["max"])
    out.append(_r("DEP-001", cat, "Dependency trong ngưỡng cho phép", FAIL if problems else PASS,
                  "; ".join(problems) or f"counts={dict(counts)}", top_findings=top[:20]))
    results = report.get("Results") or []
    r = _r("DEP-002", cat, "Trivy fs thực sự quét được dependency", PASS if results else FAIL,
           f"{len(results)} target" if results else
           "Trivy fs không tìm thấy lockfile nào (Gradle chưa bật dependency locking) => bằng chứng rỗng")
    r.severity = cfg["coverage_action"]
    out.append(r)
    return out


# =============================================================== SECRETS / SAST

def rule_secrets(ctx: Context) -> list[RuleResult]:
    cfg = ctx.rule_cfg("secrets")
    data = ctx.ev.data("gitleaks")
    if not isinstance(data, list):
        return [_r("SEC-001", "secrets", "Không lộ secret", FAIL, "Không đọc được gitleaks.json")]
    n = len(data)
    rules = sorted({f.get("RuleID", "?") for f in data if isinstance(f, dict)})
    return [_r("SEC-001", "secrets", "Không lộ secret", FAIL if n > cfg["max_findings"] else PASS,
               f"{n} finding (tối đa {cfg['max_findings']})", rules=rules)]


def rule_sast(ctx: Context) -> list[RuleResult]:
    cfg = ctx.rule_cfg("sast")
    data = ctx.ev.data("semgrep")
    if not isinstance(data, dict):
        return [_r("SAST-001", "sast", "SAST trong ngưỡng", FAIL, "Không đọc được semgrep.json")]
    counts = Counter(((r.get("extra") or {}).get("severity") or "INFO").upper()
                     for r in data.get("results") or [])
    problems = _threshold_problems(counts, cfg["max"])
    errors = [f"{r.get('check_id', '').split('.')[-1]} @ {r.get('path')}:{(r.get('start') or {}).get('line')}"
              for r in data.get("results") or []
              if ((r.get("extra") or {}).get("severity") or "").upper() == "ERROR"]
    return [_r("SAST-001", "sast", "SAST trong ngưỡng", FAIL if problems else PASS,
               "; ".join(problems) or f"counts={dict(counts)}",
               counts=dict(counts), errors=errors[:20], scan_errors=len(data.get("errors") or []))]


# =============================================================== CONSISTENCY

def rule_consistency(ctx: Context) -> list[RuleResult]:
    """Các evidence độc lập phải cùng mô tả MỘT lần build: cùng commit."""
    sources = {
        "verification.json": ctx.verification.get("commit"),
        "signature cert": ctx.cache.get("signer_commit"),
        "provenance": ctx.cache.get("provenance_commit"),
        "trivy-deps": ((ctx.ev.data("trivy_deps") or {}).get("Metadata") or {}).get("Commit"),
    }
    known = {k: v for k, v in sources.items() if v}
    if len(known) < 2:
        return [_r("CONS-001", "consistency", "Evidence nhất quán về commit", SKIP,
                   f"Chỉ có {len(known)} nguồn commit, không đủ để đối chiếu", sources=known)]
    same = len(set(known.values())) == 1
    return [_r("CONS-001", "consistency", "Evidence nhất quán về commit", PASS if same else FAIL,
               f"Commit {next(iter(known.values()))[:7]} khớp {len(known)} nguồn" if same
               else "Các evidence trỏ tới commit khác nhau => có thể bị ghép từ nhiều lần build",
               sources=known)]


# Thứ tự quan trọng: signature/provenance điền cache commit cho CONS-001
RULES: list[tuple[str, Callable[[Context], list[RuleResult]]]] = [
    ("evidence", rule_evidence_required),
    ("evidence", rule_digest_known),
    ("signature", rule_signature),
    ("sbom", rule_sbom),
    ("provenance", rule_provenance),
    ("vulnerabilities", rule_vulnerabilities),
    ("dependencies", rule_dependencies),
    ("secrets", rule_secrets),
    ("sast", rule_sast),
    ("consistency", rule_consistency),
]
