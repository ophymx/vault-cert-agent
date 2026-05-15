package source

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/vault"
)

// Letsencrypt fetches certs from vault-plugin-letsencrypt. The plugin
// exposes a read-only endpoint that issues lazily on first read and
// re-issues whenever alt_names differs from what's stored — so the
// agent's job is just GET with the configured alt_names.
type Letsencrypt struct {
	client *vault.Client
}

// NewLetsencrypt returns an LE source bound to the given Vault client.
func NewLetsencrypt(c *vault.Client) *Letsencrypt { return &Letsencrypt{client: c} }

// Fetch reads cert.LEPath, supplying alt_names as a comma-joined query
// parameter when set. The plugin treats an omitted alt_names as
// "reuse stored," so we only attach the param when the config has
// entries — that way an LE cert with no alt_names stays idempotent
// across reads without falsely triggering re-issue.
//
// The plugin's response embeds the entire chain (leaf + intermediates)
// in one `certificate` field — no separate ca_chain array like PKI.
// splitBundle peels the leaf off the front so the writer can lay out
// cert / ca files separately.
func (l *Letsencrypt) Fetch(ctx context.Context, cert config.CertConfig) (*Material, error) {
	var params url.Values
	if len(cert.AltNames) > 0 {
		params = url.Values{"alt_names": []string{strings.Join(cert.AltNames, ",")}}
	}
	resp, err := l.client.Read(ctx, cert.LEPath, params)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt read %s: %w", cert.LEPath, err)
	}
	if resp.Data == nil {
		return nil, fmt.Errorf("letsencrypt read %s: empty data in response", cert.LEPath)
	}

	bundle, err := stringField(resp.Data, "certificate")
	if err != nil {
		return nil, err
	}
	key, err := stringField(resp.Data, "private_key")
	if err != nil {
		return nil, err
	}

	leaf, chain, err := splitBundle(bundle)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt %s: %w", cert.LEPath, err)
	}
	return &Material{
		Cert: leaf,
		Key:  ensureNewline(key),
		CA:   chain,
	}, nil
}

// splitBundle peels the leaf off the front of a concatenated PEM
// bundle and returns the remaining blocks as a single chain bundle.
// Errors if there are zero PEM blocks or any block is the wrong type.
func splitBundle(bundle string) (leaf, chain []byte, err error) {
	rest := []byte(bundle)
	for i := 0; ; i++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("PEM block %d is %s, want CERTIFICATE", i, block.Type)
		}
		encoded := pem.EncodeToMemory(block)
		if i == 0 {
			leaf = encoded
		} else {
			chain = append(chain, encoded...)
		}
	}
	if leaf == nil {
		return nil, nil, errors.New("no PEM blocks found")
	}
	return leaf, chain, nil
}
