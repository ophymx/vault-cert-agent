package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ophymx/vault-cert-agent/internal/config"
)

const (
	testLoginPath = "auth/approle/login"
	testToken     = "test-client-token"
)

// writeCreds writes role_id and secret_id files into t.TempDir and
// returns the VaultConfig pointing at them.
func writeCreds(t *testing.T, url string) config.VaultConfig {
	t.Helper()
	dir := t.TempDir()
	roleFile := filepath.Join(dir, "role_id")
	secretFile := filepath.Join(dir, "secret_id")
	if err := os.WriteFile(roleFile, []byte("rid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("sid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return config.VaultConfig{
		URL:          url,
		RoleIDFile:   roleFile,
		SecretIDFile: secretFile,
		LoginPath:    testLoginPath,
	}
}

// loginHandler implements the AppRole login endpoint and asserts the
// posted body matches the on-disk creds.
func loginHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/v1/"+testLoginPath; got != want {
			t.Errorf("login path: got %q, want %q", got, want)
		}
		body, _ := io.ReadAll(r.Body)
		var creds map[string]string
		if err := json.Unmarshal(body, &creds); err != nil {
			t.Fatalf("login body not JSON: %v", err)
		}
		if creds["role_id"] != "rid" || creds["secret_id"] != "sid" {
			t.Errorf("login creds: got %v", creds)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"auth":{"client_token":"` + testToken + `"}}`))
	}
}

func TestNewClient_LoginExtractsToken(t *testing.T) {
	srv := httptest.NewServer(loginHandler(t))
	t.Cleanup(srv.Close)

	c, err := NewClient(context.Background(), writeCreds(t, srv.URL), testLogger(t))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := c.api.Token(); got != testToken {
		t.Errorf("token: got %q, want %q", got, testToken)
	}
}

func TestClient_Write_SendsTokenAndBody(t *testing.T) {
	var captured struct {
		token string
		body  map[string]any
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+testLoginPath, loginHandler(t))
	mux.HandleFunc("/v1/pki/issue/role", func(w http.ResponseWriter, r *http.Request) {
		captured.token = r.Header.Get("X-Vault-Token")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured.body)
		_, _ = w.Write([]byte(`{"data":{"hello":"world"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := NewClient(context.Background(), writeCreds(t, srv.URL), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Write(context.Background(), "pki/issue/role", map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if captured.token != testToken {
		t.Errorf("X-Vault-Token: got %q, want %q", captured.token, testToken)
	}
	if got := captured.body["k"]; got != "v" {
		t.Errorf("body[k]: got %v, want %q", got, "v")
	}
	if got := resp.Data["hello"]; got != "world" {
		t.Errorf("response: got %v, want %q", got, "world")
	}
}

func TestClient_DoesNotRetryOnHTTPError(t *testing.T) {
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+testLoginPath, loginHandler(t))
	mux.HandleFunc("/v1/bad", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, `{"errors":["denied"]}`, http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := NewClient(context.Background(), writeCreds(t, srv.URL), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(context.Background(), "bad", nil); err == nil {
		t.Fatal("expected error from 403, got nil")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("HTTP-error retry fired: got %d hits, want 1", got)
	}
}

// Network-failure tests assert behaviour only, not server-side hit
// counts. Go's net/http Transport silently re-dials idempotent
// requests when a pooled connection dies, so an exact attempt count
// would couple the test to Transport internals.

func TestClient_RetriesOnNetworkError(t *testing.T) {
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+testLoginPath, loginHandler(t))
	mux.HandleFunc("/v1/flaky", func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := NewClient(context.Background(), writeCreds(t, srv.URL), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Read(context.Background(), "flaky", nil)
	if err != nil {
		t.Fatalf("Read should recover from one network failure: %v", err)
	}
	if resp.Data["ok"] != true {
		t.Errorf("response.Data: got %v", resp.Data)
	}
}

func TestNewClient_RefusesWorldReadableSecretFile(t *testing.T) {
	srv := httptest.NewServer(loginHandler(t))
	t.Cleanup(srv.Close)

	cfg := writeCreds(t, srv.URL)
	// Loosen permissions on secret_id — agent should refuse rather
	// than silently authenticate with a credential the world can read.
	if err := os.Chmod(cfg.SecretIDFile, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := NewClient(context.Background(), cfg, testLogger(t))
	if err == nil {
		t.Fatal("expected error when secret_id is world-readable")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Errorf("error should mention mode: %v", err)
	}
}

func TestNewClient_RefusesSymlinkedSecretFile(t *testing.T) {
	srv := httptest.NewServer(loginHandler(t))
	t.Cleanup(srv.Close)

	cfg := writeCreds(t, srv.URL)
	// Replace role_id with a symlink to a same-permission decoy. The
	// O_NOFOLLOW open in readSecret refuses regardless of perms.
	decoy := cfg.RoleIDFile + ".decoy"
	if err := os.WriteFile(decoy, []byte("rid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.RoleIDFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, cfg.RoleIDFile); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(context.Background(), cfg, testLogger(t)); err == nil {
		t.Fatal("expected error when role_id is a symlink")
	}
}

func TestClient_GivesUpAfterRetry(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+testLoginPath, loginHandler(t))
	mux.HandleFunc("/v1/dead", func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := NewClient(context.Background(), writeCreds(t, srv.URL), testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Read(context.Background(), "dead", nil)
	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	// vault/api uses retryablehttp's PassthroughErrorHandler, so the
	// last underlying error (EOF here, since we hijack and close every
	// connection) bubbles up after MaxRetries+1 failed attempts.
	if !strings.Contains(err.Error(), "EOF") {
		t.Errorf("error message should surface underlying EOF: %v", err)
	}
}
