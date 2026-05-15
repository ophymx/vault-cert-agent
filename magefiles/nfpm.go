//go:build mage

package main

import (
	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"
)

func nfpmInfo(arch, version string) *nfpm.Info {
	return &nfpm.Info{
		Name:       "vault-cert-agent",
		Arch:       arch,
		Platform:   "linux",
		Version:    version,
		Release:    "1",
		Section:    "admin",
		Priority:   "optional",
		Maintainer: "Jeffrey T. Peckham <abic@ophymx.com>",
		Description: "vault-cert-agent fetches TLS material from HashiCorp Vault and writes\n" +
			"it to disk for local consumers (postgres, haproxy, pgpool, etc.).\n" +
			".\n" +
			"Replaces the older vault-pki-renew and vault-cert-renew bash scripts\n" +
			"with a single typed Go implementation driven by a systemd timer that\n" +
			"runs hourly.\n",
		Overridables: nfpm.Overridables{
			Contents: files.Contents{
				{
					Source:      "dist/bin/vault-cert-agent",
					Destination: "/usr/sbin/vault-cert-agent",
					FileInfo:    &files.ContentFileInfo{Mode: 0o755},
				},
				{
					Source:      "packaging/vault-cert-agent.service",
					Destination: "/usr/lib/systemd/system/vault-cert-agent.service",
					FileInfo:    &files.ContentFileInfo{Mode: 0o644},
				},
				{
					Source:      "packaging/vault-cert-agent.timer",
					Destination: "/usr/lib/systemd/system/vault-cert-agent.timer",
					FileInfo:    &files.ContentFileInfo{Mode: 0o644},
				},
				{
					Source:      "packaging/config.example.hcl",
					Destination: "/usr/share/doc/vault-cert-agent/config.example.hcl",
					FileInfo:    &files.ContentFileInfo{Mode: 0o644},
				},
				// /etc/vault-cert-agent is a ghost dir: the package
				// reserves the path but postinstall.sh actually
				// creates it with 0700 root:root so the AppRole
				// credentials operators drop in won't be readable
				// by other users.
				{
					Destination: "/etc/vault-cert-agent",
					Type:        "ghost",
					FileInfo:    &files.ContentFileInfo{Mode: 0o700},
				},
			},
			Scripts: nfpm.Scripts{
				PostInstall: "packaging/scripts/postinstall.sh",
				PreRemove:   "packaging/scripts/preremove.sh",
				PostRemove:  "packaging/scripts/postremove.sh",
			},
		},
	}
}
