package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ophymx/vault-cert-agent/internal/config"
)

// fakeLEServer registers a handler at /v1/<lePath> that captures the
// request's URL query and returns the supplied JSON body.
func fakeLEServer(t *testing.T, lePath string, captureURL *string, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+testLoginPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"auth":{"client_token":"` + testToken + `"}}`))
	})
	mux.HandleFunc("/v1/"+lePath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != testToken {
			t.Errorf("X-Vault-Token: got %q, want %q", got, testToken)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method: got %s, want GET", r.Method)
		}
		if captureURL != nil {
			*captureURL = r.URL.String()
		}
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// Two valid CERTIFICATE blocks (synthetic — content is junk but PEM
// encoding is correct). pem.Decode parses both.
const twoBlockBundle = "-----BEGIN CERTIFICATE-----\n" +
	"bGVhZi1ieXRlcw==\n" + // base64("leaf-bytes")
	"-----END CERTIFICATE-----\n" +
	"-----BEGIN CERTIFICATE-----\n" +
	"aW50LWJ5dGVz\n" + // base64("int-bytes")
	"-----END CERTIFICATE-----\n"

const keyPEM = "-----BEGIN PRIVATE KEY-----\n" +
	"a2V5LWJ5dGVz\n" + // base64("key-bytes")
	"-----END PRIVATE KEY-----\n"

func TestLE_Fetch_SendsAltNamesAsCommaJoinedQueryParam(t *testing.T) {
	var capturedURL string
	srv := fakeLEServer(t, "letsencrypt/certs/dns-01/home/cloudflare/db.example.com", &capturedURL,
		`{"data":{"certificate":"`+escape(twoBlockBundle)+`","private_key":"`+escape(keyPEM)+`"}}`)

	le := NewLetsencrypt(newTestClient(t, srv.URL))
	_, err := le.Fetch(context.Background(), config.CertConfig{
		Source:   config.SourceLetsencrypt,
		LEPath:   "letsencrypt/certs/dns-01/home/cloudflare/db.example.com",
		AltNames: []string{"db0.example.com", "db1.example.com", "db2.example.com"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// alt_names should be one comma-joined value, not three repeated params.
	if !strings.Contains(capturedURL, "alt_names=db0.example.com%2Cdb1.example.com%2Cdb2.example.com") {
		t.Errorf("expected comma-joined alt_names in query, got %q", capturedURL)
	}
}

func TestLE_Fetch_OmitsAltNamesWhenEmpty(t *testing.T) {
	var capturedURL string
	srv := fakeLEServer(t, "letsencrypt/certs/dns-01/home/cloudflare/db.example.com", &capturedURL,
		`{"data":{"certificate":"`+escape(twoBlockBundle)+`","private_key":"`+escape(keyPEM)+`"}}`)

	le := NewLetsencrypt(newTestClient(t, srv.URL))
	_, err := le.Fetch(context.Background(), config.CertConfig{
		Source: config.SourceLetsencrypt,
		LEPath: "letsencrypt/certs/dns-01/home/cloudflare/db.example.com",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Omitting alt_names entirely is meaningful to the plugin —
	// it means "reuse stored alt_names on renewal."
	if strings.Contains(capturedURL, "alt_names") {
		t.Errorf("alt_names should be absent from query when empty, got %q", capturedURL)
	}
}

func TestLE_Fetch_SplitsBundleIntoLeafAndChain(t *testing.T) {
	srv := fakeLEServer(t, "letsencrypt/certs/dns-01/home/cloudflare/db.example.com", nil,
		`{"data":{"certificate":"`+escape(twoBlockBundle)+`","private_key":"`+escape(keyPEM)+`"}}`)

	le := NewLetsencrypt(newTestClient(t, srv.URL))
	m, err := le.Fetch(context.Background(), config.CertConfig{
		Source: config.SourceLetsencrypt,
		LEPath: "letsencrypt/certs/dns-01/home/cloudflare/db.example.com",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	certStr := string(m.Cert)
	caStr := string(m.CA)
	if !strings.Contains(certStr, "bGVhZi1ieXRlcw==") {
		t.Errorf("leaf missing from Cert: %s", certStr)
	}
	if strings.Contains(certStr, "aW50LWJ5dGVz") {
		t.Errorf("Cert should contain ONLY the leaf, but has intermediate: %s", certStr)
	}
	if !strings.Contains(caStr, "aW50LWJ5dGVz") {
		t.Errorf("intermediate missing from CA: %s", caStr)
	}
	if strings.Contains(caStr, "bGVhZi1ieXRlcw==") {
		t.Errorf("CA should contain ONLY the chain, but has leaf: %s", caStr)
	}
	if !strings.HasSuffix(certStr, "\n") {
		t.Errorf("Cert should end in newline: %q", certStr)
	}
	if !strings.HasSuffix(caStr, "\n") {
		t.Errorf("CA should end in newline: %q", caStr)
	}
}

func TestLE_Fetch_NoPEMBlocks_Errors(t *testing.T) {
	srv := fakeLEServer(t, "letsencrypt/x", nil,
		`{"data":{"certificate":"not a PEM","private_key":"`+escape(keyPEM)+`"}}`)
	le := NewLetsencrypt(newTestClient(t, srv.URL))
	_, err := le.Fetch(context.Background(), config.CertConfig{
		Source: config.SourceLetsencrypt,
		LEPath: "letsencrypt/x",
	})
	if err == nil {
		t.Fatal("expected error for non-PEM certificate field")
	}
	if !strings.Contains(err.Error(), "no PEM blocks") {
		t.Errorf("error should mention missing PEM blocks: %v", err)
	}
}

func TestLE_Fetch_NonCertBlockType_Errors(t *testing.T) {
	// Bundle that begins with an RSA PUBLIC KEY block instead of a
	// CERTIFICATE — should be rejected outright rather than silently
	// promoted to "leaf."
	bogus := "-----BEGIN RSA PUBLIC KEY-----\nbGVhZi1ieXRlcw==\n-----END RSA PUBLIC KEY-----\n"
	srv := fakeLEServer(t, "letsencrypt/x", nil,
		`{"data":{"certificate":"`+escape(bogus)+`","private_key":"`+escape(keyPEM)+`"}}`)
	le := NewLetsencrypt(newTestClient(t, srv.URL))
	_, err := le.Fetch(context.Background(), config.CertConfig{
		Source: config.SourceLetsencrypt,
		LEPath: "letsencrypt/x",
	})
	if err == nil {
		t.Fatal("expected error for non-CERTIFICATE PEM type")
	}
	if !strings.Contains(err.Error(), "want CERTIFICATE") {
		t.Errorf("error should call out wrong block type: %v", err)
	}
}

// escape replaces the literal newlines in PEM strings with \n escape
// sequences so the result is a valid JSON string body.
func escape(s string) string {
	return strings.ReplaceAll(s, "\n", `\n`)
}
