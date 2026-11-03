# Số liệu cần thu (BƯỚC 10.2) — tổng hợp

| Số liệu | Kết quả | Nguồn |
|---|---|---|
| Thời gian admission có/không có Kyverno verify | Xem `admission-timing-summary.tsv` (20 lần/case, tách lần đầu và các lần sau) | `admission-timing-with-policy.tsv`, `admission-timing-without-policy.tsv` |
| Lead time commit → chạy trên cluster | ~10 phút (push → Argo CD sync Succeeded 10:01) | `lead-time-K1.md` |
| Thời gian job `promote` | 14 giây | `lead-time-K1.md` |
| Thời gian canary + analysis | Healthy: canary → Healthy ~1:52 (K1). Lỗi: canary nhận traffic → abort ~51 giây (K10) | `lead-time-K1.md`, `K10-canary-rollback.txt` |
| Tài nguyên của các công cụ | Bảng bên dưới | Prometheus (cAdvisor) |
| So sánh Trivy CI và Trivy Harbor | Khớp 100% trên cả hai digest | Bảng bên dưới |

## Tài nguyên theo namespace — 2026-11-03T08:30:00Z

Cluster kind 1 node (8 CPU, ~10.7 GiB RAM). Chưa cài metrics-server nên lấy từ cAdvisor qua Prometheus
(`container_cpu_usage_seconds_total`, `container_memory_working_set_bytes`), tương đương `kubectl top`.
CPU tính bằng millicore; "TB 1h" là trung bình 1 giờ, "max 1h" là đỉnh bộ nhớ trong 1 giờ.

| Namespace | Pod | CPU hiện tại | CPU TB 1h | RAM hiện tại (MiB) | RAM max 1h (MiB) |
|---|---|---|---|---|---|
| kube-system (apiserver, etcd, …) | 8 | 239 | 232 | 1670 | 1729 |
| monitoring (Prometheus, Grafana, Loki, Alloy, Alertmanager) | 9 | 78 | 74 | 1619 | 1740 |
| harbor | 9 | 151 | 31 | 438 | 438 |
| argocd | 6 | 12 | 17 | 390 | 714 |
| demo (ứng dụng) | 2 | 13 | 12 | 292 | 292 |
| kyverno | 4 | 23 | 23 | 271 | 285 |
| vault | 1 | 26 | 22 | 185 | 200 |
| external-secrets | 3 | 6 | 5 | 175 | 178 |
| falco | 3 | 40 | 67 | 154 | 167 |
| argo-rollouts | 2 | 3 | 2 | 78 | 82 |
| loadgen | 1 | 74 | 67 | 8 | 9 |
| local-path-storage | 1 | 0 | 0 | 19 | 19 |
| **Tổng** | **49** | **664** | **552** | **5299** | — |

- Phần bổ sung của đồ án (Harbor, Argo CD, Argo Rollouts, Kyverno, Vault, External Secrets, Falco, monitoring) chiếm khoảng 3,3 GiB RAM, gấp ~11 lần bản thân ứng dụng demo (292 MiB).
- CPU hiện tại của Harbor (151m) cao hơn trung bình 1h (31m) vì lúc đo Harbor vừa chạy Trivy quét 2 image cho bảng dưới.
- argocd đạt đỉnh 714 MiB lúc sync liên tục trong các kịch bản K3/K10.

## Trivy CI và Trivy Harbor trên cùng digest

Image là OCI index (manifest linux/amd64 + attestation của buildx). CI quét theo digest index; Harbor (proxy cache project `ghcr`)
lưu và quét manifest con linux/amd64, nên đối chiếu theo cặp index ↔ manifest con.

| Image | Digest index (CI) | Manifest linux/amd64 (Harbor) | Trivy CI 0.70.0 | Trivy Harbor 0.75.0 |
|---|---|---|---|---|
| Bản sạch (đang chạy, run 41586366923, ALLOWED) | `sha256:98392352…d40e` | `sha256:e5eb4bde…75ee` | 0 CVE | 0 CVE |
| Bản K2 (Tomcat 11.0.24 / Jackson 3.1.5, run 41575607913, BLOCKED) | `sha256:8be5233e…0c3a` | `sha256:719f5070…c35f` | 11 (4 Critical, 5 High, 2 Medium) | 11 (4 Critical, 5 High, 2 Medium) |

Danh sách CVE của bản K2 trùng khớp từng mã ở cả hai bên:

| Mức | CVE | Gói | Phiên bản |
|---|---|---|---|
| Critical | CVE-2026-65182 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.24 |
| Critical | CVE-2026-65637 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.24 |
| Critical | CVE-2026-65905 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.24 |
| Critical | CVE-2026-68525 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.24 |
| High | CVE-2026-68497 | tools.jackson.core:jackson-databind | 3.1.5 |
| High | CVE-2026-91776 | tools.jackson.core:jackson-databind | 3.1.5 |
| High | CVE-2026-91777 | tools.jackson.core:jackson-databind | 3.1.5 |
| High | CVE-2026-89407 | tools.jackson.core:jackson-core | 3.1.5 |
| High | CVE-2026-89425 | tools.jackson.core:jackson-core | 3.1.5 |
| Medium | CVE-2026-19032 | tools.jackson.core:jackson-databind | 3.1.5 |
| Medium | CVE-2026-83557 | tools.jackson.core:jackson-databind | 3.1.5 |

Thời điểm quét: CI 04:02:57Z (K2) và 05:53:53Z (bản sạch); Harbor 08:26–08:29Z. Khác phiên bản Trivy (0.70.0 và 0.75.0) và cách nhau
~4 giờ nhưng kết quả giống nhau, nên quét lại ở registry không thay đổi quyết định của Trust Engine với hai image này.

Ghi chú: các artifact `scan=Error` trong project `ghcr` của Harbor là manifest attestation (platform unknown/unknown) của buildx,
Trivy không quét được; không phải lỗi của image ứng dụng.
