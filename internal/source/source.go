// Package source defines the cert-source abstraction. Each Source
// fetches TLS material (leaf cert, private key, CA chain) from a
// specific Vault endpoint shape. The renewer dispatches per cert via
// a Registry keyed on the config's `source` field.
package source

import (
	"context"
	"fmt"
	"strings"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/vault"
)

// Material is the PEM-encoded output of a successful Fetch. CA is the
// full chain back to a root that's in the system trust store, joined
// into a single PEM bundle — never the issuing-CA alone.
type Material struct {
	Cert []byte
	Key  []byte
	CA   []byte
}

// Source fetches Material for one cert. Implementations live in this
// package, one file per Vault endpoint shape.
type Source interface {
	Fetch(ctx context.Context, cert config.CertConfig) (*Material, error)
}

// Registry resolves a config source name (e.g. "pki") to a Source
// impl. Adding a new source = new file, new impl, new line here.
type Registry struct {
	impls map[string]Source
}

// NewRegistry wires every supported source to a shared Vault client.
func NewRegistry(client *vault.Client) *Registry {
	return &Registry{
		impls: map[string]Source{
			config.SourcePKI:         NewPKI(client),
			config.SourceLetsencrypt: NewLetsencrypt(client),
		},
	}
}

// For returns the Source for the given config name. The renewer calls
// this once per cert.
func (r *Registry) For(name string) (Source, error) {
	s, ok := r.impls[name]
	if !ok {
		return nil, fmt.Errorf("unknown source %q", name)
	}
	return s, nil
}

// stringField extracts a non-empty string-typed key from a Vault
// response's `data` map. Shared by all source impls.
func stringField(data map[string]any, key string) (string, error) {
	raw, ok := data[key]
	if !ok {
		return "", fmt.Errorf("response missing %q", key)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("response %q is %T, want string", key, raw)
	}
	if s == "" {
		return "", fmt.Errorf("response %q is empty", key)
	}
	return s, nil
}

// ensureNewline returns s as []byte with exactly one trailing
// newline. Used to normalise PEM strings before they hit the writer.
func ensureNewline(s string) []byte {
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return []byte(s)
}
