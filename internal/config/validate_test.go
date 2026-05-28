package config

import (
	"strings"
	"testing"
)

func baseConfig() *Config {
	c := &Config{
		Vault: VaultConfig{
			URL:          "https://vault.example.com",
			RoleIDFile:   "/etc/x/role_id",
			SecretIDFile: "/etc/x/secret_id",
		},
		Renewal: &RenewalConfig{ThresholdFraction: 0.25},
		Certs:   []CertConfig{baseCert()},
	}
	return c
}

func TestValidate_VaultURLMustBeHTTPS(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"http", "http://vault.example.com"},
		{"no-scheme", "vault.example.com"},
		{"missing-host", "https://"},
		{"ftp", "ftp://vault.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseConfig()
			c.Vault.URL = tc.url
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error for url=%q", tc.url)
			}
			if !strings.Contains(err.Error(), "vault.url") {
				t.Errorf("error should mention vault.url, got %v", err)
			}
		})
	}
}

func TestValidate_VaultURLHTTPSAccepted(t *testing.T) {
	c := baseConfig()
	c.Vault.URL = "https://vault.example.com:8200"
	if err := c.Validate(); err != nil {
		t.Errorf("unexpected error for valid https url: %v", err)
	}
}

func baseCert() CertConfig {
	return CertConfig{
		Name:        "c",
		Source:      SourcePKI,
		Destination: "/etc/c",
		Format:      FormatSplit,
		Owner:       "root:root",
		Mode:        "0600",
		Files:       &FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
		PKIMount:    "pki",
		PKIRole:     "r",
		CommonName:  "host.example.com",
		TTL:         "24h",
	}
}

func TestValidate_BothReloadFieldsRejected(t *testing.T) {
	c := baseCert()
	c.ReloadCommand = []string{"systemctl", "reload", "foo"}
	c.ReloadUnits = []string{"foo.service"}
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "at most one of reload_command and reload_units") {
		t.Errorf("expected mutual-exclusion error, got %v", err)
	}
}

func TestValidate_EmptyReloadCommandExecutableRejected(t *testing.T) {
	c := baseCert()
	c.ReloadCommand = []string{"   ", "arg"}
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "reload_command[0]") {
		t.Errorf("expected empty-executable error, got %v", err)
	}
}

func TestValidate_ReloadMethodWithoutUnitsRejected(t *testing.T) {
	c := baseCert()
	c.ReloadMethod = ReloadMethodReload
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "reload_method only applies") {
		t.Errorf("expected reload_method-without-units error, got %v", err)
	}
}

func TestValidate_EmptyReloadUnitsEntryRejected(t *testing.T) {
	c := baseCert()
	c.ReloadUnits = []string{"a.service", "  "}
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "reload_units[1] is empty") {
		t.Errorf("expected empty-entry error, got %v", err)
	}
}

func TestValidate_UnknownReloadMethodRejected(t *testing.T) {
	c := baseCert()
	c.ReloadUnits = []string{"a.service"}
	c.ReloadMethod = "kick"
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "unknown reload_method") {
		t.Errorf("expected unknown-method error, got %v", err)
	}
}

func TestValidate_BundleOrderOnSplitRejected(t *testing.T) {
	c := baseCert()
	c.BundleOrder = BundleOrderCertChainKey
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "bundle_order only applies to format=combined") {
		t.Errorf("expected bundle_order-on-split error, got %v", err)
	}
}

func TestValidate_UnknownBundleOrderRejected(t *testing.T) {
	c := baseCert()
	c.Format = FormatCombined
	c.Files = nil // combined rejects files block
	c.Destination = "/etc/c/bundle.pem"
	c.BundleOrder = "key-only"
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "unknown bundle_order") {
		t.Errorf("expected unknown-bundle_order error, got %v", err)
	}
}

func TestValidate_AllKnownBundleOrdersAccepted(t *testing.T) {
	for _, order := range []string{
		BundleOrderCertChainKey,
		BundleOrderCertKeyChain,
		BundleOrderKeyCertChain,
		BundleOrderKeyChainCert,
		BundleOrderChainCertKey,
		BundleOrderChainKeyCert,
	} {
		t.Run(order, func(t *testing.T) {
			c := baseCert()
			c.Format = FormatCombined
			c.Files = nil // combined rejects files block
			c.Destination = "/etc/c/bundle.pem"
			c.BundleOrder = order
			if err := c.validate(); err != nil {
				t.Errorf("unexpected error for %q: %v", order, err)
			}
		})
	}
}

func TestValidate_SplitRequiresFilesBlock(t *testing.T) {
	c := baseCert()
	c.Files = nil
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "files block is required") {
		t.Errorf("expected files-required error, got %v", err)
	}
}

func TestValidate_FilesBlockMustNameAtLeastOneSlot(t *testing.T) {
	c := baseCert()
	c.Files = &FilesOverride{}
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("expected ≥1-slot error, got %v", err)
	}
}

func TestValidate_FilesRejectsPathSeparators(t *testing.T) {
	cases := []struct {
		name  string
		mod   func(*FilesOverride)
		field string
	}{
		{"subdir", func(f *FilesOverride) { f.Cert = "sub/node.crt" }, "files.cert"},
		{"absolute", func(f *FilesOverride) { f.Key = "/etc/elsewhere/node.key" }, "files.key"},
		{"parent traversal", func(f *FilesOverride) { f.CA = ".." }, "files.ca"},
		{"current dir", func(f *FilesOverride) { f.Fullchain = "." }, "files.fullchain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseCert()
			c.Files = &FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"}
			tc.mod(c.Files)
			err := c.validate()
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Errorf("expected %s error, got %v", tc.field, err)
			}
		})
	}
}

func TestValidate_FilesRejectsCollisions(t *testing.T) {
	c := baseCert()
	c.Files = &FilesOverride{
		Cert:      "bundle.pem",
		Key:       "key.pem",
		Fullchain: "bundle.pem", // same as Cert
	}
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "both resolve to") {
		t.Errorf("expected collision error, got %v", err)
	}
}

func TestValidate_FilesAcceptsPartialDeclarations(t *testing.T) {
	// Only fullchain + key — the non-AIA-aware-client recipe.
	c := baseCert()
	c.Files = &FilesOverride{Key: "tls.key", Fullchain: "fullchain.pem"}
	if err := c.validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_CombinedRejectsFilesBlock(t *testing.T) {
	c := baseCert()
	c.Format = FormatCombined
	c.Destination = "/etc/c/bundle.pem"
	// Files inherited from baseCert; should be rejected for combined.
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "files block is only valid with format=split") {
		t.Errorf("expected combined-rejects-files error, got %v", err)
	}
}

func TestValidate_ValidReloadConfigurationsAccepted(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c *CertConfig)
	}{
		{"none", func(c *CertConfig) {}},
		{"exec only", func(c *CertConfig) { c.ReloadCommand = []string{"systemctl", "reload", "x"} }},
		{"systemd default method", func(c *CertConfig) { c.ReloadUnits = []string{"x.service"} }},
		{"systemd explicit method", func(c *CertConfig) {
			c.ReloadUnits = []string{"x.service"}
			c.ReloadMethod = ReloadMethodRestart
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseCert()
			tc.mod(&c)
			if err := c.validate(); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
