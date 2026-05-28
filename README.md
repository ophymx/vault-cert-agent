# vault-cert-agent

A one-shot Go binary that fetches TLS material from HashiCorp Vault and
writes it to disk for local consumers (postgres, haproxy, pgpool, etc.).
Runs hourly under a systemd timer; skips work when certs are still fresh.

Replaces a pair of bash renewers with a single typed implementation.

## Supported cert sources

| source        | Vault endpoint                                | notes                                    |
| ------------- | --------------------------------------------- | ---------------------------------------- |
| `pki`         | `POST {mount}/issue/{role}`                   | Vault's built-in PKI engine.             |
| `letsencrypt` | `GET {path}` on [vault-plugin-letsencrypt][1] | Plugin does ACME; this agent just reads. |

[1]: https://github.com/ophymx/vault-plugin-letsencrypt

Adding a new source is one file in `internal/source/` plus one line in
`NewRegistry`.

## Install

Each tagged release publishes `linux_amd64.deb` and `linux_arm64.deb`
on the [GitHub Releases page](https://github.com/ophymx/vault-cert-agent/releases),
alongside `.tar.gz` archives and a `checksums.txt`.

```
# from a release asset
sudo dpkg -i vault-cert-agent_*.deb

# or, if the package is mirrored into an apt repo
sudo apt install vault-cert-agent
```

The package installs:

- `/usr/sbin/vault-cert-agent` — the binary
- `/usr/lib/systemd/system/vault-cert-agent.{service,timer}` — single-instance unit, oneshot + hourly trigger
- `/usr/lib/systemd/system/vault-cert-agent@.{service,timer}` — templated unit for hosts with multiple independent agents
- `/etc/vault-cert-agent/` — config directory, mode `0700 root:root`
- `/usr/share/doc/vault-cert-agent/config.example.hcl` — annotated example

The single-instance timer is enabled and started on first install.
Upgrades leave the existing enabled/disabled state alone. `apt purge`
removes `/etc/vault-cert-agent/` (including the AppRole credentials)
along with the package files.

## Configure

Drop three files into `/etc/vault-cert-agent/`:

| file         | content                            | required mode  |
| ------------ | ---------------------------------- | -------------- |
| `role_id`    | Vault AppRole role_id              | `0600` (no group/other) |
| `secret_id`  | Vault AppRole secret_id            | `0600` (no group/other) |
| `config.hcl` | config (see [`config.example.hcl`](packaging/config.example.hcl)) | `0644` typical |

The agent refuses to start if `role_id` or `secret_id` has any
group/other access bits set, or if the path is a symlink — both would
mean the AppRole identity is already outside the agent's trust boundary.
`vault.url` must use `https://`; an `http://` value is rejected at
config load.

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
  files {
    cert = "node.crt"
    key  = "node.key"
    ca   = "ca.crt"
  }
  owner          = "postgres:postgres"
  mode           = "0600"
  reload_command = ["systemctl", "try-reload-or-restart", "pg_agentd.service"]
}
```

### Multiple instances on one host

For hosts that need independently-scheduled agents — e.g. a host
serving both database and metrics certs from different Vault
AppRoles — use the templated unit. Each instance gets its own
subdirectory under `/etc/vault-cert-agent/`:

```
/etc/vault-cert-agent/
├── db/
│   ├── config.hcl
│   ├── role_id
│   └── secret_id
└── metrics/
    ├── config.hcl
    ├── role_id
    └── secret_id
```

Enable + start each instance independently:

```
systemctl enable --now vault-cert-agent@db.timer
systemctl enable --now vault-cert-agent@metrics.timer
```

The templated `ExecStart` passes `-config /etc/vault-cert-agent/%i/config.hcl`,
so each instance's `vault { role_id_file = ... }` should point at the
files under that instance's subdirectory. The single-instance unit
(`vault-cert-agent.service`) and the templated form (`vault-cert-agent@.service`)
can coexist on the same host without conflict.

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

### Split format: declaring output files

`format = "split"` requires a `files { ... }` block. Every file you
want emitted must be named explicitly — unnamed slots are not
written, and there are no source-derived defaults. The available
slots:

| slot        | content                                          |
| ----------- | ------------------------------------------------ |
| `cert`      | leaf cert only                                   |
| `key`       | private key                                      |
| `ca`        | chain (intermediate(s) + root from the source)   |
| `fullchain` | leaf + chain concatenated (no key)               |

Each value is a plain basename — no path separators, no `..`, no
absolute paths. All values must be unique (a two-slot collision is a
config error). The block must declare at least one slot.

Typical declarations:

```hcl
# Conventional split layout for a postgres consumer.
files {
  cert = "node.crt"
  key  = "node.key"
  ca   = "ca.crt"
}

# Non-AIA-aware client (postgres, older JVMs): the TLS server needs to
# present the intermediate itself, so emit a fullchain and skip the
# leaf-only and ca files entirely.
files {
  key       = "tls.key"
  fullchain = "fullchain.pem"
}
```

The same `owner` / `mode` apply to every file the block produces.

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

### Write semantics

Writes are atomic: temp file in the destination directory, `chmod` and
`chown` applied to the open fd, then `rename` into place. Readers never
see a partial or wrong-permissioned file.

Permissions are re-enforced on every run even when the content hasn't
changed — fixes a perm-drift bug the bash scripts had.

The agent runs as root and chowns cert files to per-consumer owners,
so it refuses to operate on symlinks (or any non-regular file) at cert
paths. Without this, a low-privileged consumer with write access to a
cert directory could plant a symlink in place of a cert file and steer
the next run's chmod/chown at an arbitrary target. If that error fires,
investigate the path before redeploying.

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

For a local debug binary:

```
go build -o vault-cert-agent ./cmd/vault-cert-agent
```

For a release-shape build (binary + `.deb` + tarball under `dist/`)
without tagging or publishing, use [goreleaser](https://goreleaser.com/):

```
goreleaser release --snapshot --clean
```

Requires Go 1.26+ and goreleaser v2+. The version string is derived
from `git describe`; snapshot builds get a `<next>-snapshot+<sha>`
suffix.

## Release

Push a `vX.Y.Z` tag and the `release` GitHub Actions workflow runs
goreleaser, which builds linux/amd64 + linux/arm64 binaries, packs
`.tar.gz` archives, builds `.deb` packages, and publishes a GitHub
Release with changelog + checksums.

## Tests

```
go test ./...
```

## License

[MIT](LICENSE).
