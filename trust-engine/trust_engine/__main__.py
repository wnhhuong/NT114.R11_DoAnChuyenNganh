"""CLI: python -m trust_engine evaluate --evidence DIR --policy FILE [...]

Exit code: 0 = ALLOWED, 1 = BLOCKED, 2 = lỗi engine/policy (fail-closed).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .engine import ALLOWED, evaluate
from .evidence import load_evidence
from .policy import PolicyError, load_policy
from .report import to_markdown


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="trust_engine")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("evaluate", help="Đánh giá evidence theo policy")
    e.add_argument("--evidence", required=True, help="Thư mục chứa evidence (tìm đệ quy)")
    e.add_argument("--policy", required=True)
    e.add_argument("--image", help="vd ghcr.io/owner/repo (chữ thường)")
    e.add_argument("--digest", help="sha256:... của image cần đánh giá")
    e.add_argument("--now", help="Thời điểm đánh giá ISO-8601 (để tái lập kết quả)")
    e.add_argument("--out", default="decision.json")
    e.add_argument("--markdown", help="Ghi thêm báo cáo Markdown")
    e.add_argument("--no-fail", action="store_true", help="Luôn exit 0 (dùng khi replay)")
    args = p.parse_args(argv)

    try:
        policy = load_policy(args.policy)
        ev = load_evidence(args.evidence)
        now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else None
        if now and now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        decision = evaluate(policy, ev, image=args.image, digest=args.digest, now=now)
    except (PolicyError, FileNotFoundError, ValueError) as exc:
        print(f"[trust-engine] ERROR: {exc}", file=sys.stderr)
        return 2

    Path(args.out).write_text(json.dumps(decision, indent=2, ensure_ascii=False), encoding="utf-8")
    md = to_markdown(decision)
    if args.markdown:
        Path(args.markdown).write_text(md, encoding="utf-8")
    print(md)
    if args.no_fail:
        return 0
    return 0 if decision["decision"] == ALLOWED else 1


if __name__ == "__main__":
    sys.exit(main())
