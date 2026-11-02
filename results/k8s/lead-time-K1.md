# K1 — Luồng end-to-end commit → cluster (lần đo 1)

Commit `3d65811` → secure-ci run `41452363690` → promote commit `3c1cef1` → digest
`sha256:6350c4087814378fb94a5f1101bc5f5b0c01dbe1ad44ad6ccf64696706c6e99a` (ALLOWED, trust_score 100).

| Mốc (UTC, 2026-11-02) | Thời điểm | Từ mốc trước | Từ lúc push |
|---|---|---|---|
| Push / secure-ci bắt đầu | 13:22:05 | — | 0:00 |
| `promote` tạo commit `chore(deploy): promote 6350c4087814` | 13:27:29 | 5:24 | 5:24 |
| `promote` job xong | 13:27:33 | 0:04 | 5:28 |
| Argo CD phát hiện commit, bắt đầu sync | 13:29:19 | 1:46 | 7:14 |
| Kyverno cho qua, canary pod bắt đầu (step 0, setWeight 50) | 13:30:05 | 0:46 | 8:00 |
| Canary pause 30s (step 1) | 13:30:18 | 0:13 | 8:13 |
| AnalysisRun bắt đầu (step 2) | 13:30:50 | 0:32 | 8:45 |
| AnalysisRun Successful (3/3 lần đo đạt ≥ 95%) | 13:31:30 | 0:40 | 9:25 |
| Rollout Healthy, bản mới thành stable | 13:31:57 | 0:27 | 9:52 |
| Argo CD sync Succeeded (sau PostSync hook trust-audit) | 13:32:06 | 0:09 | 10:01 |

Thời gian từng job của secure-ci:

| Job | Bắt đầu | Kết thúc | Thời gian |
|---|---|---|---|
| Dependency scan | 13:22:08 | 13:22:20 | 0:12 |
| Code and secret scan | 13:22:18 | 13:22:57 | 0:39 |
| Build, scan, sign, and attest image | 13:23:00 | 13:25:52 | 2:52 |
| Verify image evidence | 13:26:00 | 13:26:25 | 0:25 |
| Trust evaluation and policy decision | 13:26:28 | 13:26:39 | 0:11 |
| Sign and attach trust decision | 13:26:43 | 13:27:16 | 0:33 |
| Promote ALLOWED image to GitOps manifests | 13:27:19 | 13:27:33 | 0:14 |

Bằng chứng audit (log của Job `trust-audit`, PostSync hook):

```json
{"event":"trust-decision-audit","verified":true,"run_id":"41452363690","commit":"3d658110a6326958601c2b8c359de35ea7fc9654","digest":"sha256:6350c4087814378fb94a5f1101bc5f5b0c01dbe1ad44ad6ccf64696706c6e99a","decision":"ALLOWED","trust_score":100,"policy":"default","policy_sha256":"3aa24f7a8e0743975a94f8eca0843376a3f6347cc51b8ab6bc1249a5f51f4822","violations":[]}
```

Ghi chú: khoảng chờ 1:46 giữa promote và Argo CD sync là do Argo CD poll Git (timeout.reconciliation 60s
+ jitter); không có webhook vì cluster không public. Log trạng thái chi tiết: `e2e-timeline.log`.
