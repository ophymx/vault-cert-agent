package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Validate checks that all required fields are present and well-formed.
func (c *Config) Validate() error {
	if c.Vault.URL == "" {
		return errors.New("vault.url is required")
	}
	if err := validateVaultURL(c.Vault.URL); err != nil {
		return err
	}
	if c.Vault.RoleIDFile == "" {
		return errors.New("vault.role_id_file is required")
	}
	if c.Vault.SecretIDFile == "" {
		return errors.New("vault.secret_id_file is required")
	}
	if c.Renewal.ThresholdFraction <= 0 || c.Renewal.ThresholdFraction >= 1 {
		return fmt.Errorf("renewal.threshold_fraction must be in (0,1), got %v", c.Renewal.ThresholdFraction)
	}
	if len(c.Certs) == 0 {
		return errors.New(`at least one cert "name" {...} block is required`)
	}
	seen := make(map[string]struct{}, len(c.Certs))
	for i, cert := range c.Certs {
		if err := cert.validate(); err != nil {
			label := cert.Name
			if label == "" {
				label = fmt.Sprintf("index %d", i)
			}
			return fmt.Errorf("cert %s: %w", label, err)
		}
		if _, dup := seen[cert.Name]; dup {
			return fmt.Errorf("cert %s: duplicate name", cert.Name)
		}
		seen[cert.Name] = struct{}{}
	}
	return nil
}

func (c CertConfig) validate() error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	if c.Destination == "" {
		return errors.New("destination is required")
	}
	if c.Owner == "" {
		return errors.New("owner is required")
	}
	if _, _, err := ParseOwner(c.Owner); err != nil {
		return fmt.Errorf("owner: %w", err)
	}
	if c.Mode == "" {
		return errors.New("mode is required")
	}
	if _, err := ParseMode(c.Mode); err != nil {
		return fmt.Errorf("mode: %w", err)
	}
	switch c.Format {
	case "":
		return errors.New("format is required")
	case FormatSplit:
		// any files override allowed
		if c.BundleOrder != "" {
			return errors.New("bundle_order only applies to format=combined")
		}
	case FormatCombined:
		if c.Files != nil {
			return errors.New("files override is only valid with format=split")
		}
		if c.BundleOrder != "" && !validBundleOrder(c.BundleOrder) {
			return fmt.Errorf("unknown bundle_order %q (want one of %s)",
				c.BundleOrder, strings.Join(bundleOrders, ", "))
		}
	default:
		return fmt.Errorf("unknown format %q (want %q or %q)", c.Format, FormatSplit, FormatCombined)
	}
	if err := c.validateReload(); err != nil {
		return err
	}
	switch c.Source {
	case "":
		return errors.New("source is required")
	case SourcePKI:
		if c.PKIMount == "" {
			return errors.New("pki_mount is required for source=pki")
		}
		if c.PKIRole == "" {
			return errors.New("pki_role is required for source=pki")
		}
		if c.CommonName == "" {
			return errors.New("common_name is required for source=pki")
		}
		if c.TTL == "" {
			return errors.New("ttl is required for source=pki")
		}
		if _, err := time.ParseDuration(c.TTL); err != nil {
			return fmt.Errorf("ttl: %w", err)
		}
	case SourceLetsencrypt:
		if c.LEPath == "" {
			return errors.New("le_path is required for source=letsencrypt")
		}
	default:
		return fmt.Errorf("unknown source %q (want %q or %q)", c.Source, SourcePKI, SourceLetsencrypt)
	}
	return nil
}

func (c CertConfig) validateReload() error {
	if len(c.ReloadCommand) > 0 && len(c.ReloadUnits) > 0 {
		return errors.New("set at most one of reload_command and reload_units")
	}
	if c.ReloadMethod != "" && len(c.ReloadUnits) == 0 {
		return errors.New("reload_method only applies to reload_units")
	}
	for i, u := range c.ReloadUnits {
		if strings.TrimSpace(u) == "" {
			return fmt.Errorf("reload_units[%d] is empty", i)
		}
	}
	if len(c.ReloadCommand) > 0 {
		if strings.TrimSpace(c.ReloadCommand[0]) == "" {
			return errors.New("reload_command[0] (executable) is empty")
		}
	}
	if c.ReloadMethod != "" && !validReloadMethod(c.ReloadMethod) {
		return fmt.Errorf("unknown reload_method %q (want one of %s)",
			c.ReloadMethod, strings.Join(reloadMethods, ", "))
	}
	return nil
}

var reloadMethods = []string{
	ReloadMethodReload,
	ReloadMethodRestart,
	ReloadMethodTryRestart,
	ReloadMethodReloadOrRestart,
	ReloadMethodTryReloadOrRestart,
}

func validReloadMethod(name string) bool {
	return slices.Contains(reloadMethods, name)
}

var bundleOrders = []string{
	BundleOrderCertChainKey,
	BundleOrderCertKeyChain,
	BundleOrderKeyCertChain,
	BundleOrderKeyChainCert,
	BundleOrderChainCertKey,
	BundleOrderChainKeyCert,
}

func validBundleOrder(name string) bool {
	return slices.Contains(bundleOrders, name)
}

// validateVaultURL enforces https and a non-empty host. AppRole
// secret_id rides the request body; permitting http would ship it
// in plaintext.
func validateVaultURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("vault.url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("vault.url must use https (got scheme %q in %q)", u.Scheme, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("vault.url has no host: %q", raw)
	}
	return nil
}

// ParseOwner splits "user:group" into its two parts.
func ParseOwner(s string) (user, group string, err error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected user:group, got %q", s)
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("user and group must both be non-empty: %q", s)
	}
	return parts[0], parts[1], nil
}

// ParseMode parses an octal mode string (e.g. "0600") into os.FileMode.
func ParseMode(s string) (os.FileMode, error) {
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parse octal mode %q: %w", s, err)
	}
	return os.FileMode(n), nil
}
