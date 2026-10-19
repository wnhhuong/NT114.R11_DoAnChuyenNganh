# Trust Evaluation Engine

Đánh giá security evidence của một container image theo Security Policy (YAML) và ra quyết định
`ALLOWED / TRUSTED` hoặc `BLOCKED / UNTRUSTED`.

```
evidence/ (từ secure-ci.yml)  ──►  trust_engine  ──►  decision.json + decision.md
policy/default.yaml           ──┘   (offline, deterministic, fail-closed)
```

## Chạy

```bash
pip install -r trust-engine/requirements.txt
PYTHONPATH=trust-engine python -m trust_engine evaluate \
  --evidence <thư mục evidence> \
  --policy trust-engine/policy/default.yaml \
  [--image ghcr.io/owner/repo] [--digest sha256:...] [--now 2026-10-19T00:00:00Z] \
  --out decision.json --markdown decision.md
```

Exit code: `0` ALLOWED, `1` BLOCKED, `2` lỗi engine/policy (pipeline coi là chặn).

## Test

```bash
cd trust-engine && python -m unittest discover -s tests -t . -v
```

## Cấu trúc

| File | Vai trò |
|---|---|
| `trust_engine/evidence.py` | Đọc evidence, giải mã DSSE attestation, chuẩn hóa output `gh attestation verify` |
| `trust_engine/policy.py` | Nạp + kiểm tra policy YAML, điền giá trị mặc định |
| `trust_engine/rules.py` | Các rule (EVD, SIG, SBOM, PROV, VULN, DEP, SEC, SAST, CONS) |
| `trust_engine/engine.py` | Chạy rule, tổng hợp violations/warnings, quyết định, trust score |
| `trust_engine/report.py` | Xuất Markdown cho GitHub job summary |
| `policy/default.yaml`, `policy/strict.yaml` | Hai profile policy |
