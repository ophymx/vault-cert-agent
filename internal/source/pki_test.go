package source

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/vault"
)

const (
	testLoginPath = "auth/approle/login"
	testToken     = "tok"
)

// fakeVault returns an httptest server that handles the AppRole login
// plus one configured PKI endpoint. issueHandler runs against the
// /v1/<mount>/issue/<role> path and gets the decoded request body.
func fakeVault(t *testing.T, mount, role string, issueHandler func(body map[string]any) string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+testLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"auth":{"client_token":"` + testToken + `"}}`))
	})
	mux.HandleFunc("/v1/"+mount+"/issue/"+role, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != testToken {
			t.Errorf("X-Vault-Token: got %q, want %q", got, testToken)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("issue body not JSON: %v", err)
		}
		_, _ = w.Write([]byte(issueHandler(body)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T, srvURL string) *vault.Client {
	t.Helper()
	dir := t.TempDir()
	roleFile := filepath.Join(dir, "role_id")
	secretFile := filepath.Join(dir, "secret_id")
	if err := os.WriteFile(roleFile, []byte("rid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("sid"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := vault.NewClient(context.Background(), config.VaultConfig{
		URL:          srvURL,
		RoleIDFile:   roleFile,
		SecretIDFile: secretFile,
		LoginPath:    testLoginPath,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPKI_Fetch_SendsAltNamesAsCommaString(t *testing.T) {
	var captured map[string]any
	srv := fakeVault(t, "pki", "role", func(body map[string]any) string {
		captured = body
		return `{"data":{
			"certificate":"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
			"private_key":"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
			"ca_chain":["-----BEGIN CERTIFICATE-----\nint\n-----END CERTIFICATE-----",
			           "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"]
		}}`
	})

	pki := NewPKI(newTestClient(t, srv.URL))
	_, err := pki.Fetch(context.Background(), config.CertConfig{
		Source:     config.SourcePKI,
		PKIMount:   "pki",
		PKIRole:    "role",
		CommonName: "host.example.com",
		TTL:        "24h",
		AltNames:   []string{"a.example.com", "b.example.com"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// The Vault PKI quirk: alt_names must be a comma-separated string,
	// not a JSON array. A regression here silently issues a cert with
	// no SANs because Vault drops the unknown field type.
	if got, want := captured["alt_names"], "a.example.com,b.example.com"; got != want {
		t.Errorf("alt_names: got %v (%T), want %q (string)", got, got, want)
	}
	if got := captured["common_name"]; got != "host.example.com" {
		t.Errorf("common_name: got %v", got)
	}
	if got := captured["ttl"]; got != "24h" {
		t.Errorf("ttl: got %v", got)
	}
}

func TestPKI_Fetch_OmitsAltNamesWhenEmpty(t *testing.T) {
	var captured map[string]any
	srv := fakeVault(t, "pki", "role", func(body map[string]any) string {
		captured = body
		return `{"data":{
			"certificate":"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
			"private_key":"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
			"ca_chain":["-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"]
		}}`
	})

	pki := NewPKI(newTestClient(t, srv.URL))
	_, err := pki.Fetch(context.Background(), config.CertConfig{
		Source:     config.SourcePKI,
		PKIMount:   "pki",
		PKIRole:    "role",
		CommonName: "host.example.com",
		TTL:        "24h",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, present := captured["alt_names"]; present {
		t.Errorf("alt_names should be omitted when empty, got %v", captured["alt_names"])
	}
}

func TestPKI_Fetch_AssemblesFullChain(t *testing.T) {
	srv := fakeVault(t, "pki_pg_agent", "pg-agent", func(body map[string]any) string {
		return `{"data":{
			"certificate":"-----BEGIN CERTIFICATE-----\nleaf-bytes\n-----END CERTIFICATE-----",
			"private_key":"-----BEGIN PRIVATE KEY-----\nkey-bytes\n-----END PRIVATE KEY-----",
			"ca_chain":["-----BEGIN CERTIFICATE-----\nint-bytes\n-----END CERTIFICATE-----",
			           "-----BEGIN CERTIFICATE-----\nroot-bytes\n-----END CERTIFICATE-----"]
		}}`
	})

	pki := NewPKI(newTestClient(t, srv.URL))
	m, err := pki.Fetch(context.Background(), config.CertConfig{
		PKIMount:   "pki_pg_agent",
		PKIRole:    "pg-agent",
		CommonName: "db0.example.com",
		TTL:        "24h",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if !strings.Contains(string(m.Cert), "leaf-bytes") {
		t.Errorf("Cert: %s", m.Cert)
	}
	if !strings.Contains(string(m.Key), "key-bytes") {
		t.Errorf("Key: %s", m.Key)
	}
	// The CA bundle must contain BOTH the intermediate and root, in
	// order, joined with newlines — using issuing_ca alone (the old
	// vault-pki-renew bug) would only include the intermediate.
	caStr := string(m.CA)
	intIdx := strings.Index(caStr, "int-bytes")
	rootIdx := strings.Index(caStr, "root-bytes")
	if intIdx < 0 || rootIdx < 0 {
		t.Fatalf("CA missing chain members: %s", caStr)
	}
	if intIdx > rootIdx {
		t.Errorf("CA chain out of order: intermediate at %d, root at %d", intIdx, rootIdx)
	}
	if !strings.HasSuffix(caStr, "\n") {
		t.Errorf("CA bundle should end in newline: %q", caStr)
	}
}

func TestPKI_Fetch_ErrorsOnMissingFields(t *testing.T) {
	srv := fakeVault(t, "pki", "role", func(body map[string]any) string {
		return `{"data":{"certificate":"x","private_key":"y"}}` // no ca_chain
	})
	pki := NewPKI(newTestClient(t, srv.URL))
	_, err := pki.Fetch(context.Background(), config.CertConfig{
		PKIMount: "pki", PKIRole: "role", CommonName: "h", TTL: "1h",
	})
	if err == nil {
		t.Fatal("expected error for missing ca_chain")
	}
	if !strings.Contains(err.Error(), "ca_chain") {
		t.Errorf("error should name missing field: %v", err)
	}
}
