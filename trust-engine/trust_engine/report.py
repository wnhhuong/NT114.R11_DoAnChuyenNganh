"""Xuất quyết định ra Markdown (dùng cho GitHub job summary và báo cáo)."""

from __future__ import annotations

ICON = {"pass": "✅", "skip": "⏭️"}


def _icon(rule: dict) -> str:
    if rule["status"] == "fail":
        return "❌" if rule["severity"] == "block" else "⚠️"
    return ICON.get(rule["status"], "•")


def to_markdown(d: dict) -> str:
    head = "🟢" if d["decision"] == "ALLOWED" else "🔴"
    a, s = d["artifact"], d["summary"]
    lines = [
        f"## {head} Trust Evaluation: **{d['decision']}** ({d['trust_level']})",
        "",
        f"- Image: `{a['image']}@{a['digest']}` (digest từ {a['digest_source']})",
        f"- Policy: `{d['policy']['name']}` v{d['policy']['version']} "
        f"(sha256 `{(d['policy']['sha256'] or '')[:12]}`)",
        f"- Trust score (tham khảo): **{d['trust_score']}/100**",
        f"- Rules: {s['rules']} | đạt {s['passed']} | vi phạm {s['violations']} | "
        f"cảnh báo {s['warnings']} | bỏ qua {s['skipped']}",
        f"- Thời gian đánh giá: {d['evaluation_ms']} ms",
        "",
    ]
    if d["violations"]:
        lines += ["### Vi phạm (chặn triển khai)", ""]
        lines += [f"- **{v['id']}** {v['title']}: {v['message']}" for v in d["violations"]]
        lines.append("")
    lines += ["### Chi tiết", "", "| | Rule | Nhóm | Kết quả |", "|---|---|---|---|"]
    for r in d["rules"]:
        msg = r["message"].replace("|", "\\|")
        lines.append(f"| {_icon(r)} | {r['id']} {r['title']} | {r['category']} | {msg} |")
    return "\n".join(lines) + "\n"
