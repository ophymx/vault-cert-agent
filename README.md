# vault-cert-agent

A one-shot Go binary that fetches TLS material from HashiCorp Vault and
writes it to disk for local consumers (postgres, haproxy, pgpool, etc.).
Runs hourly under a systemd timer; skips work when certs are still fresh.

Replaces two ansible-deployed bash scripts (`vault-pki-renew` and
`vault-cert-renew`) with a single typed implementation. Design notes
live in [`SPEC.md`](SPEC.md).

## Supported cert sources

| source        | Vault endpoint                                | notes                                    |
| ------------- | --------------------------------------------- | ---------------------------------------- |
| `pki`         | `POST {mount}/issue/{role}`                   | Vault's built-in PKI engine.             |
| `letsencrypt` | `GET {path}` on [vault-plugin-letsencrypt][1] | Plugin does ACME; this agent just reads. |

[1]: https://github.com/ophymx/vault-plugin-letsencrypt

Adding a new source is one file in `internal/source/` plus one line in
`NewRegistry`.

## Install

The build pipeline produces a Debian package. From the internal apt repo:

```
apt install vault-cert-agent
```

The package installs:

- `/usr/sbin/vault-cert-agent` — the binary
- `/usr/lib/systemd/system/vault-cert-agent.{service,timer}` — oneshot + hourly trigger
- `/etc/vault-cert-agent/` — config directory, mode `0700 root:root`
- `/usr/share/doc/vault-cert-agent/config.example.hcl` — annotated example

The timer is enabled and started on first install. Upgrades leave the
existing enabled/disabled state alone.

## Configure

Drop three files into `/etc/vault-cert-agent/`:

- `role_id` — Vault AppRole role_id
- `secret_id` — Vault AppRole secret_id
- `config.hcl` — config (see [`config.example.hcl`](packaging/config.example.hcl))

Minimal config:

```hcl
vault {
  url            = "https://vault.example.com"
  role_id_file   = "/etc/vault-cert-agent/role_id"
  secret_id_file = "/etc/vault-cert-agent/secret_id"
}

renewal {
  # Renew when the leaf has less than this fraction of its issued
  # lifetime remaining. Default 0.25 (renew when 75% elapsed).
  threshold_fraction = 0.25
}

cert "pg-db0" {
  source         = "pki"
  pki_mount      = "pki_pg_agent"
  pki_role       = "pg-agent"
  common_name    = "db0.example.com"
  alt_names      = ["db0.example.com"]
  ttl            = "24h"
  destination    = "/etc/pg_agent/tls"
  format         = "split"
  owner          = "postgres:postgres"
  mode           = "0600"
  reload_command = ["systemctl", "try-reload-or-restart", "pg_agentd.service"]
}
```

### Combined format

With `format = "combined"` the writer emits a single file containing
the leaf cert, the chain, and the private key concatenated. The
`bundle_order` field selects the layout — default `cert-chain-key`
(what HAProxy's `crt` directive expects). Valid values:

| value              | layout                  | typical consumer        |
| ------------------ | ----------------------- | ----------------------- |
| `cert-chain-key`   | leaf, chain, key        | HAProxy (default)       |
| `cert-key-chain`   | leaf, key, chain        |                         |
| `key-cert-chain`   | key, leaf, chain        |                         |
| `key-chain-cert`   | key, chain, leaf        |                         |
| `chain-cert-key`   | chain, leaf, key        |                         |
| `chain-key-cert`   | chain, key, leaf        |                         |

`bundle_order` is rejected with `format = "split"`.

### Reload action

Each cert can specify exactly one of two reload styles (or neither):

| field            | how it runs                                                                  |
| ---------------- | ---------------------------------------------------------------------------- |
| `reload_command` | argv list, executed directly. **No shell.** No word splitting, no `$VAR` expansion, no pipes — wrap in `["/bin/sh", "-c", "..."]` to opt in. |
| `reload_units`   | list of systemd units, issued as a D-Bus job on the system bus.              |

The systemd path goes through `org.freedesktop.systemd1` on the
polkit-mediated system bus — **not** the `/run/systemd/private` root-
bypass socket — so calls are auditable and operators can constrain
them via polkit rules. With `reload_units`, `reload_method` selects
the verb (default `try-reload-or-restart`; valid: `reload`, `restart`,
`try-restart`, `reload-or-restart`, `try-reload-or-restart`).

```hcl
reload_units  = ["pgpool2.service", "haproxy.service"]
reload_method = "try-reload-or-restart"
```

Writes are atomic (temp file in the destination directory → `chmod` →
`chown` → `rename`). Permissions are re-enforced on every run even when
the content hasn't changed, which fixes a perm-drift bug the bash
scripts had.

## Run

The systemd timer drives normal operation. Manual invocation for
debugging:

```
vault-cert-agent [flags]

  -config string   path to config (default "/etc/vault-cert-agent/config.hcl")
  -dry-run         report what would happen; don't fetch or write
  -force           ignore TTL threshold; refetch every cert
  -verbose         log per-cert decision rationale (sets level=debug)
  -log-format      "text" (default) or "json"
  -version         print version and exit
```

Exit codes:

| code | meaning                                                  |
| ---- | -------------------------------------------------------- |
| 0    | every cert checked, none failed                          |
| 1    | startup failure (bad config, vault auth, etc.)           |
| 2    | partial failure — at least one cert failed; others ran   |

Logs go to stderr (so `journalctl -u vault-cert-agent.service` captures
them) via `log/slog`.

## Build from source

```
mage build    # compile linux binary into dist/bin/
mage package  # build + produce a .deb under dist/pkg/
mage clean    # remove dist/
```

Requires Go 1.26+ and [mage](https://magefile.org/). Version string
comes from `git describe --tags --dirty --always`; falls back to
`0.0.0-dev`.

## Tests

```
go test ./...
```
