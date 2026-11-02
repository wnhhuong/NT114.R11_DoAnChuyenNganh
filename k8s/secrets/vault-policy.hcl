# Least privilege cho External Secrets: chỉ đọc secret có tiền tố nt114/ (KV v2 tại secret/)
path "secret/data/nt114/*" {
  capabilities = ["read"]
}

path "secret/metadata/nt114/*" {
  capabilities = ["read"]
}
