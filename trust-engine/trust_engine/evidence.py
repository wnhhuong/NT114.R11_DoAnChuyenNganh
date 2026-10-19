"""Đọc và chuẩn hóa security evidence do secure-ci.yml sinh ra.

Engine KHÔNG gọi cosign/gh. Việc xác minh mật mã do workflow (job verify /
trust-evaluation) thực hiện; module này chỉ đọc kết quả đã ghi ra file, giải mã
DSSE envelope và đưa về một cấu trúc thống nhất cho các rule.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Tên logic -> tên file trong thư mục evidence (khớp với tên file upload trong secure-ci.yml)
EVIDENCE_FILES: dict[str, str] = {
    "verification": "verification.json",        # job verify: trạng thái 3-4 phép verify
    "signature": "signature-verify.json",       # cosign verify (stdout JSON)
    "sbom_attestation": "sbom-verify.json",     # cosign verify-attestation --type cyclonedx
    "vuln_attestation": "vuln-verify.json",     # cosign verify-attestation --type vuln (mới)
    "provenance": "provenance-verify.json",     # gh attestation verify --format json (mới)
    "sbom": "sbom.cdx.json",                    # Syft, bản upload artifact
    "vuln_report": "vuln.cosign.json",          # Trivy image, bản upload artifact
    "semgrep": "semgrep.json",
    "gitleaks": "gitleaks.json",
    "trivy_deps": "trivy-deps.json",
}

PRESENT, MISSING, EMPTY, INVALID = "present", "missing", "empty", "invalid"

PREDICATE_CYCLONEDX = "https://cyclonedx.org/bom"
PREDICATE_VULN = "https://cosign.sigstore.dev/attestation/vuln/v1"
PREDICATE_SLSA_PREFIX = "https://slsa.dev/provenance/"


@dataclass
class EvidenceItem:
    name: str
    filename: str
    status: str = MISSING
    path: str | None = None
    sha256: str | None = None
    data: Any = None
    error: str | None = None

    def ok(self) -> bool:
        return self.status == PRESENT

    def to_dict(self) -> dict:
        return {
            "file": self.filename,
            "status": self.status,
            "path": self.path,
            "sha256": self.sha256,
            "error": self.error,
        }


@dataclass
class EvidenceBundle:
    root: str
    items: dict[str, EvidenceItem] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def get(self, name: str) -> EvidenceItem:
        return self.items[name]

    def data(self, name: str) -> Any:
        item = self.items.get(name)
        return item.data if item and item.ok() else None


def _parse_json_or_jsonl(text: str) -> Any:
    """cosign verify-attestation in mỗi attestation một dòng JSON -> hỗ trợ cả JSON và JSONL."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        return rows


def _find_file(root: Path, filename: str, notes: list[str]) -> Path | None:
    direct = root / filename
    if direct.is_file():
        return direct
    matches = sorted(p for p in root.rglob(filename) if p.is_file())
    if not matches:
        return None
    if len(matches) > 1:
        notes.append(f"Có {len(matches)} file {filename}; dùng {matches[0]}")
    return matches[0]


def load_evidence(root: str | Path) -> EvidenceBundle:
    root_path = Path(root)
    bundle = EvidenceBundle(root=str(root_path))
    if not root_path.is_dir():
        raise FileNotFoundError(f"Thư mục evidence không tồn tại: {root_path}")

    for name, filename in EVIDENCE_FILES.items():
        item = EvidenceItem(name=name, filename=filename)
        path = _find_file(root_path, filename, bundle.notes)
        if path is not None:
            raw = path.read_bytes()
            item.path = str(path)
            item.sha256 = hashlib.sha256(raw).hexdigest()
            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                item.status = EMPTY
            else:
                try:
                    item.data = _parse_json_or_jsonl(text)
                    item.status = PRESENT
                except json.JSONDecodeError as exc:
                    item.status = INVALID
                    item.error = f"JSON không hợp lệ: {exc}"
        bundle.items[name] = item
    return bundle


# ---------------------------------------------------------------- helpers cho rule

def as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def decode_dsse_statements(envelopes: Any) -> list[dict]:
    """Giải mã output của `cosign verify-attestation` (DSSE envelope, payload base64)."""
    statements = []
    for env in as_list(envelopes):
        if not isinstance(env, dict) or "payload" not in env:
            continue
        try:
            statements.append(json.loads(base64.b64decode(env["payload"])))
        except (ValueError, json.JSONDecodeError):
            continue
    return statements


def pick_statement(statements: list[dict], predicate_prefix: str, digest: str | None) -> dict | None:
    """Chọn statement đúng predicateType và (nếu biết) đúng digest của image."""
    candidates = [s for s in statements if str(s.get("predicateType", "")).startswith(predicate_prefix)]
    if digest:
        bare = digest.split(":", 1)[-1]
        for s in candidates:
            for subj in as_list(s.get("subject")):
                if (subj.get("digest") or {}).get("sha256") == bare:
                    return s
    return candidates[0] if candidates else None


def statement_digests(statement: dict | None) -> list[str]:
    if not statement:
        return []
    return [
        "sha256:" + d["digest"]["sha256"]
        for d in as_list(statement.get("subject"))
        if isinstance(d, dict) and (d.get("digest") or {}).get("sha256")
    ]


def _walk(obj: Any):
    """Duyệt mọi dict lồng nhau (output của gh có thể đổi cấu trúc giữa các phiên bản)."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def provenance_entries(data: Any) -> list[dict]:
    """Chuẩn hóa output `gh attestation verify --format json` thành list {statement, certificate}.

    Cấu trúc thường gặp: [{"attestation": {...}, "verificationResult": {"statement": {...},
    "signature": {"certificate": {...runnerEnvironment, sourceRepositoryDigest...}}}}].
    Tìm kiếm đệ quy để không phụ thuộc cứng vào tên field bọc ngoài.
    """
    out = []
    for row in as_list(data):
        statement = next((d for d in _walk(row)
                          if "predicateType" in d and "subject" in d), None)
        cert = next((d for d in _walk(row) if "runnerEnvironment" in d
                     or "sourceRepositoryDigest" in d), {})
        if statement:
            out.append({"statement": statement, "certificate": cert})
    return out


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))
