package source

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/vault"
)

// PKI fetches certs from Vault's built-in PKI engine via
// POST <mount>/issue/<role>.
type PKI struct {
	client *vault.Client
}

// NewPKI returns a PKI source bound to the given Vault client.
func NewPKI(c *vault.Client) *PKI { return &PKI{client: c} }

// Fetch issues a new cert from the configured PKI mount/role.
//
// Vault PKI takes alt_names as a comma-separated *string*, not an
// array — passing an array silently issues a cert with no SANs.
// And the chain comes back as `ca_chain` (array of PEMs); the older
// `issuing_ca` field is the issuing intermediate only and produces a
// trust-chain hole.
func (p *PKI) Fetch(ctx context.Context, cert config.CertConfig) (*Material, error) {
	body := map[string]any{
		"common_name": cert.CommonName,
		"ttl":         cert.TTL,
	}
	if len(cert.AltNames) > 0 {
		body["alt_names"] = strings.Join(cert.AltNames, ",")
	}

	resp, err := p.client.Write(ctx, path.Join(cert.PKIMount, "issue", cert.PKIRole), body)
	if err != nil {
		return nil, fmt.Errorf("pki issue %s/%s: %w", cert.PKIMount, cert.PKIRole, err)
	}
	if resp.Data == nil {
		return nil, fmt.Errorf("pki issue %s/%s: empty data in response", cert.PKIMount, cert.PKIRole)
	}

	leaf, err := stringField(resp.Data, "certificate")
	if err != nil {
		return nil, err
	}
	key, err := stringField(resp.Data, "private_key")
	if err != nil {
		return nil, err
	}
	chain, err := chainField(resp.Data, "ca_chain")
	if err != nil {
		return nil, err
	}

	return &Material{
		Cert: ensureNewline(leaf),
		Key:  ensureNewline(key),
		CA:   ensureNewline(chain),
	}, nil
}

// chainField pulls a JSON array of PEM strings and joins them with a
// trailing newline between entries so the result is a valid
// concatenated PEM bundle.
func chainField(data map[string]any, key string) (string, error) {
	raw, ok := data[key]
	if !ok {
		return "", fmt.Errorf("response missing %q", key)
	}
	items, ok := raw.([]any)
	if !ok {
		return "", fmt.Errorf("response %q is %T, want array", key, raw)
	}
	if len(items) == 0 {
		return "", fmt.Errorf("response %q is empty", key)
	}
	var b strings.Builder
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return "", fmt.Errorf("response %q[%d] is %T, want string", key, i, item)
		}
		b.WriteString(s)
		if !strings.HasSuffix(s, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}
