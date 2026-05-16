// Package config loads and validates the vault-cert-agent HCL config.
package config

import (
	"fmt"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// Source values for CertConfig.Source.
const (
	SourcePKI         = "pki"
	SourceLetsencrypt = "letsencrypt"
)

// Format values for CertConfig.Format.
const (
	FormatSplit    = "split"
	FormatCombined = "combined"
)

// BundleOrder values for CertConfig.BundleOrder. Only meaningful with
// format=combined; selects the concatenation order of the three PEM
// blobs in the output file. HAProxy wants cert-chain-key; other
// consumers vary, so all six permutations are spelled out.
const (
	BundleOrderCertChainKey = "cert-chain-key"
	BundleOrderCertKeyChain = "cert-key-chain"
	BundleOrderKeyCertChain = "key-cert-chain"
	BundleOrderKeyChainCert = "key-chain-cert"
	BundleOrderChainCertKey = "chain-cert-key"
	BundleOrderChainKeyCert = "chain-key-cert"
)

// DefaultBundleOrder matches the historical hard-coded order
// (cert + chain + key) — what HAProxy's `crt` directive consumes.
const DefaultBundleOrder = BundleOrderCertChainKey

// ReloadMethod values for CertConfig.ReloadMethod. Each maps to the
// systemctl verb of the same name (and the corresponding D-Bus method
// on org.freedesktop.systemd1.Manager).
const (
	ReloadMethodReload             = "reload"
	ReloadMethodRestart            = "restart"
	ReloadMethodTryRestart         = "try-restart"
	ReloadMethodReloadOrRestart    = "reload-or-restart"
	ReloadMethodTryReloadOrRestart = "try-reload-or-restart"
)

// DefaultReloadMethod is used when reload_units is set without
// reload_method. Mirrors the bash scripts' habit of using
// `systemctl try-reload-or-restart`.
const DefaultReloadMethod = ReloadMethodTryReloadOrRestart

const (
	defaultLoginPath         = "auth/approle/login"
	defaultThresholdFraction = 0.25
)

// Config is the top-level configuration loaded from HCL.
type Config struct {
	Vault   VaultConfig    `hcl:"vault,block"`
	Renewal *RenewalConfig `hcl:"renewal,block"`
	Certs   []CertConfig   `hcl:"cert,block"`
}

// VaultConfig holds Vault connection and AppRole auth settings.
type VaultConfig struct {
	URL          string `hcl:"url"`
	RoleIDFile   string `hcl:"role_id_file"`
	SecretIDFile string `hcl:"secret_id_file"`
	LoginPath    string `hcl:"login_path,optional"`
}

// RenewalConfig holds the renewal-decision parameters.
type RenewalConfig struct {
	ThresholdFraction float64 `hcl:"threshold_fraction,optional"`
}

// CertConfig is one `cert "name" { ... }` block. Fields are flat across
// sources; which ones are required depends on Source.
type CertConfig struct {
	Name        string         `hcl:"name,label"`
	Source      string         `hcl:"source"`
	Destination string         `hcl:"destination"`
	Format      string         `hcl:"format"`
	Files       *FilesOverride `hcl:"files,block"`
	Owner       string         `hcl:"owner"`
	Mode        string         `hcl:"mode"`

	// BundleOrder controls the PEM concatenation order in combined
	// format. Empty falls back to DefaultBundleOrder. Rejected with
	// format=split.
	BundleOrder string `hcl:"bundle_order,optional"`

	// Reload action. At most one of ReloadCommand and ReloadUnits may
	// be set. ReloadMethod (with defaults to DefaultReloadMethod) only
	// applies to the ReloadUnits path.
	ReloadCommand string   `hcl:"reload_command,optional"`
	ReloadUnits   []string `hcl:"reload_units,optional"`
	ReloadMethod  string   `hcl:"reload_method,optional"`

	// pki source fields.
	PKIMount   string   `hcl:"pki_mount,optional"`
	PKIRole    string   `hcl:"pki_role,optional"`
	CommonName string   `hcl:"common_name,optional"`
	TTL        string   `hcl:"ttl,optional"`
	AltNames   []string `hcl:"alt_names,optional"`

	// letsencrypt source fields.
	LEPath string `hcl:"le_path,optional"`
}

// FilesOverride lets a cert override the three split-format filenames.
// Absent block = use the source's default names.
type FilesOverride struct {
	Cert string `hcl:"cert,optional"`
	Key  string `hcl:"key,optional"`
	CA   string `hcl:"ca,optional"`
}

// Load reads, decodes, applies defaults, and validates a config file.
func Load(path string) (*Config, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse %s: %s", path, diags.Error())
	}
	var c Config
	if diags := gohcl.DecodeBody(file.Body, nil, &c); diags.HasErrors() {
		return nil, fmt.Errorf("decode %s: %s", path, diags.Error())
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Vault.LoginPath == "" {
		c.Vault.LoginPath = defaultLoginPath
	}
	if c.Renewal == nil {
		c.Renewal = &RenewalConfig{}
	}
	if c.Renewal.ThresholdFraction == 0 {
		c.Renewal.ThresholdFraction = defaultThresholdFraction
	}
}
