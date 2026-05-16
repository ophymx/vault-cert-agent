# vault-cert-agent config — example.
#
# Default location: /etc/vault-cert-agent/config.hcl
# Override with `vault-cert-agent -config /path/to/config.hcl`.

vault {
  url            = "https://vault.example.com"
  role_id_file   = "/etc/vault-cert-agent/role_id"
  secret_id_file = "/etc/vault-cert-agent/secret_id"
  # login_path defaults to "auth/approle/login". Override if your
  # AppRole mount lives elsewhere.
  # login_path   = "auth/approle/login"
}

renewal {
  # Renew when the leaf cert has less than this fraction of its issued
  # lifetime remaining. Default 0.25.
  threshold_fraction = 0.25
}


# ─── Vault PKI source ─────────────────────────────────────────────
# Issues from a Vault PKI engine. Renewed in place each run when the
# cert is below the TTL threshold.
cert "pg-agent-db0" {
  source         = "pki"
  pki_mount      = "pki_pg_agent"
  pki_role       = "pg-agent"
  common_name    = "db0.example.com"
  alt_names      = ["db0.example.com"]
  ttl            = "24h"
  destination    = "/etc/pg_agent/tls"
  format         = "split"
  # Per-file name overrides (optional, only with format=split).
  # Defaults for source=pki: node.crt / node.key / ca.crt.
  # files {
  #   cert = "node.crt"
  #   key  = "node.key"
  #   ca   = "ca.crt"
  # }
  owner          = "postgres:postgres"
  mode           = "0600"
  # Reload action. Two options, mutually exclusive:
  #   reload_command — argv list. Direct exec, no shell — no word
  #                    splitting, no $variable expansion, no pipes.
  #                    Wrap in /bin/sh -c explicitly if you need a shell.
  #   reload_units   — list of systemd units, talked to via the
  #                    polkit-authorised system bus (NOT the
  #                    /run/systemd/private root-bypass socket).
  # When using reload_units, reload_method defaults to
  # "try-reload-or-restart"; valid values: reload, restart, try-restart,
  # reload-or-restart, try-reload-or-restart.
  reload_command = ["systemctl", "try-reload-or-restart", "pg_agentd.service"]
  # reload_units  = ["pg_agentd.service"]
  # reload_method = "try-reload-or-restart"
}


# ─── LetsEncrypt source (vault-plugin-letsencrypt) ────────────────
# Fetches an ACME-issued cert stored at a fixed Vault path. The
# plugin handles ACME challenges; this agent only reads + writes.
# Changing alt_names triggers a re-issue.
cert "db-cluster-le" {
  source         = "letsencrypt"
  le_path        = "letsencrypt/certs/dns-01/home/cloudflare/db.example.com"
  alt_names = [
    "db0.example.com",
    "db1.example.com",
    "db2.example.com",
  ]
  destination    = "/etc/pgpool2/tls"
  format         = "split"
  # Defaults for source=letsencrypt: tls.crt / tls.key / ca.crt.
  owner          = "postgres:postgres"
  mode           = "0600"
  # Same reload-action options as above; this cert uses the systemd
  # D-Bus path. reload_method defaults to "try-reload-or-restart".
  reload_units   = ["pgpool2.service"]
}


# ─── HAProxy-style combined bundle ────────────────────────────────
# format=combined writes one file with the three PEM blobs
# concatenated. bundle_order picks the layout; default
# "cert-chain-key" matches HAProxy's `crt` directive. Valid values:
#   cert-chain-key, cert-key-chain, key-cert-chain,
#   key-chain-cert, chain-cert-key, chain-key-cert.
cert "edge-haproxy" {
  source         = "letsencrypt"
  le_path        = "letsencrypt/certs/dns-01/home/cloudflare/edge.example.com"
  destination    = "/etc/haproxy/certs/edge.pem"
  format         = "combined"
  bundle_order   = "cert-chain-key"
  owner          = "haproxy:haproxy"
  mode           = "0600"
  reload_units   = ["haproxy.service"]
}
