package config

import (
	"strings"
	"testing"
)

func baseCert() CertConfig {
	return CertConfig{
		Name:        "c",
		Source:      SourcePKI,
		Destination: "/etc/c",
		Format:      FormatSplit,
		Owner:       "root:root",
		Mode:        "0600",
		PKIMount:    "pki",
		PKIRole:     "r",
		CommonName:  "host.example.com",
		TTL:         "24h",
	}
}

func TestValidate_BothReloadFieldsRejected(t *testing.T) {
	c := baseCert()
	c.ReloadCommand = "systemctl reload foo"
	c.ReloadUnits = []string{"foo.service"}
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "at most one of reload_command and reload_units") {
		t.Errorf("expected mutual-exclusion error, got %v", err)
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
			c.Destination = "/etc/c/bundle.pem"
			c.BundleOrder = order
			if err := c.validate(); err != nil {
				t.Errorf("unexpected error for %q: %v", order, err)
			}
		})
	}
}

func TestValidate_ValidReloadConfigurationsAccepted(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c *CertConfig)
	}{
		{"none", func(c *CertConfig) {}},
		{"shell only", func(c *CertConfig) { c.ReloadCommand = "systemctl reload x" }},
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
