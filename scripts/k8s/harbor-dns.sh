#!/usr/bin/env bash
# Cho node (containerd) và Pod (CoreDNS) phân giải harbor.nt114.local -> ClusterIP của Harbor,
# và cho containerd pull qua HTTP. Chạy lại sau khi cài lại Harbor hoặc restart Docker Desktop.
set -euo pipefail
HOST="harbor.nt114.local"
PORT="30002"
NODE="${KIND_NODE:-nt114-control-plane}"

IP=$(kubectl -n harbor get svc harbor -o jsonpath='{.spec.clusterIP}')
echo "Harbor ClusterIP: $IP"

# 1) /etc/hosts của node — containerd dùng khi pull. File này là bind mount nên không dùng sed -i.
docker exec "$NODE" sh -c "grep -v ' $HOST\$' /etc/hosts > /tmp/hosts.new; echo '$IP $HOST' >> /tmp/hosts.new; cat /tmp/hosts.new > /etc/hosts"

# 2) containerd: registry HTTP
docker exec "$NODE" mkdir -p "/etc/containerd/certs.d/$HOST:$PORT"
docker exec -i "$NODE" sh -c "cat > '/etc/containerd/certs.d/$HOST:$PORT/hosts.toml'" <<EOF
server = "http://$HOST:$PORT"

[host."http://$HOST:$PORT"]
  capabilities = ["pull", "resolve"]
EOF

# 3) CoreDNS: chèn (hoặc thay) block hosts ngay sau dòng ".:53 {"
kubectl -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' \
  | awk -v ip="$IP" -v host="$HOST" '
      /# nt114-harbor-begin/ { skip = 1 }
      !skip { print }
      /# nt114-harbor-end/ { skip = 0; next }
      /^\.:53 \{/ && !done {
        print "    # nt114-harbor-begin"
        print "    hosts {"
        print "       " ip " " host
        print "       fallthrough"
        print "    }"
        print "    # nt114-harbor-end"
        done = 1
      }' > /tmp/Corefile

kubectl -n kube-system create configmap coredns --from-file=Corefile=/tmp/Corefile \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kube-system rollout restart deploy/coredns
kubectl -n kube-system rollout status deploy/coredns
rm -f /tmp/Corefile
echo "OK: $HOST -> $IP"
