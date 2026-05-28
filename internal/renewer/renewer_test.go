package renewer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/reload"
	"github.com/ophymx/vault-cert-agent/internal/source"
	"github.com/ophymx/vault-cert-agent/internal/writer"
)

// fakeSource is a Source impl that records each Fetch call.
type fakeSource struct {
	calls    atomic.Int32
	material *source.Material
	err      error
}

func (f *fakeSource) Fetch(ctx context.Context, cert config.CertConfig) (*source.Material, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.material, nil
}

// fakeSources implements renewer.Sources for tests.
type fakeSources struct {
	src source.Source
	by  func(name string) source.Source
}

func (f *fakeSources) For(name string) (source.Source, error) {
	if f.by != nil {
		return f.by(name), nil
	}
	return f.src, nil
}

func writePEMCert(t *testing.T, path string, notBefore, notAfter time.Time, dnsNames []string) {
	t.Helper()
	writePEMCertBlocks(t, path, notBefore, notAfter, dnsNames, 1)
}

// writePEMCertWithChain writes a leaf CERTIFICATE block followed by a
// second CERTIFICATE block (a self-signed stand-in for an intermediate)
// — the on-disk shape produced by the writer's fullchain slot.
func writePEMCertWithChain(t *testing.T, path string, notBefore, notAfter time.Time, dnsNames []string) {
	t.Helper()
	writePEMCertBlocks(t, path, notBefore, notAfter, dnsNames, 2)
}

func writePEMCertBlocks(t *testing.T, path string, notBefore, notAfter time.Time, dnsNames []string, blocks int) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < blocks; i++ {
		chainTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: "intermediate"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}
		chainDER, err := x509.CreateCertificate(rand.Reader, chainTmpl, chainTmpl, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: chainDER}); err != nil {
			t.Fatal(err)
		}
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testOwner(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return u.Username + ":" + g.Name
}

// fakeFetchMaterial returns a Material whose PEMs are syntactically
// valid (writer doesn't care about content correctness).
func fakeFetchMaterial(t *testing.T, dnsNames []string) *source.Material {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &source.Material{
		Cert: leafPEM,
		Key:  keyPEM,
		CA:   leafPEM, // self-signed; reuse leaf as chain for the test
	}
}

// ─────────────────────────────────────────────────────────────────
// Decision tests — these don't need a registry; they call decide()
// directly with a hand-built Renewer.

func newDecideRenewer(t *testing.T, opts Options, now time.Time) *Renewer {
	t.Helper()
	r := New(nil, nil, nil, discardLogger(), opts)
	r.SetClock(func() time.Time { return now })
	return r
}

func TestDecide_NoExistingCertFetches(t *testing.T) {
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, time.Now())
	d := r.decide(cert, discardLogger())
	if !d.fetch {
		t.Errorf("missing cert should fetch, got skip: %s", d.reason)
	}
}

func TestDecide_FreshCertSkips(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	// 100-day cert, on day 10. 90% remaining; threshold 0.25.
	writePEMCert(t, filepath.Join(dir, "node.crt"),
		now.AddDate(0, 0, -10), now.AddDate(0, 0, 90),
		[]string{"host.example.com"})

	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	if d := r.decide(cert, discardLogger()); d.fetch {
		t.Errorf("fresh cert should skip, got fetch: %s", d.reason)
	}
}

func TestDecide_FreshFullchainSlotSkips(t *testing.T) {
	// Happy path for the fullchain branch: on-disk file contains
	// leaf + chain, config declares the fullchain slot, TTL is fresh.
	// Must skip — not be confused into refetching by the shape check.
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	writePEMCertWithChain(t, filepath.Join(dir, "fullchain.pem"),
		now.AddDate(0, 0, -10), now.AddDate(0, 0, 90),
		[]string{"host.example.com"})
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Key: "tls.key", Fullchain: "fullchain.pem"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	if d := r.decide(cert, discardLogger()); d.fetch {
		t.Errorf("fresh fullchain should skip, got fetch: %s", d.reason)
	}
}

func TestDecide_CertSlotConfiguredButOnDiskHasChainFetches(t *testing.T) {
	// Operator flipped fullchain -> cert on the same filename. The
	// leaf TTL is fresh, but the file's still a fullchain — we must
	// refetch+rewrite to bring it back to leaf-only.
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	writePEMCertWithChain(t, filepath.Join(dir, "node.crt"),
		now.AddDate(0, 0, -10), now.AddDate(0, 0, 90),
		[]string{"host.example.com"})
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	d := r.decide(cert, discardLogger())
	if !d.fetch {
		t.Fatalf("shape mismatch should fetch, got skip: %s", d.reason)
	}
	if !strings.Contains(d.reason, "contains a chain") {
		t.Errorf("expected shape-mismatch reason, got %q", d.reason)
	}
}

func TestDecide_FullchainSlotConfiguredButOnDiskLeafOnlyFetches(t *testing.T) {
	// Operator flipped cert -> fullchain on the same filename. The
	// leaf TTL is fresh, but the file's still leaf-only — refetch so
	// the rewrite appends the chain.
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	writePEMCert(t, filepath.Join(dir, "node.crt"),
		now.AddDate(0, 0, -10), now.AddDate(0, 0, 90),
		[]string{"host.example.com"})
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Key: "tls.key", Fullchain: "node.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	d := r.decide(cert, discardLogger())
	if !d.fetch {
		t.Fatalf("shape mismatch should fetch, got skip: %s", d.reason)
	}
	if !strings.Contains(d.reason, "no chain") {
		t.Errorf("expected shape-mismatch reason, got %q", d.reason)
	}
}

func TestDecide_StaleCertFetches(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	// 100-day cert, on day 80. 20% remaining; threshold 0.25.
	writePEMCert(t, filepath.Join(dir, "node.crt"),
		now.AddDate(0, 0, -80), now.AddDate(0, 0, 20),
		[]string{"host.example.com"})

	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	if d := r.decide(cert, discardLogger()); !d.fetch {
		t.Errorf("stale cert should fetch, got skip: %s", d.reason)
	}
}

func TestDecide_ThresholdBoundaryIsInclusive(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	// 100-day cert, on day 75 exactly → remaining_fraction == 0.25.
	writePEMCert(t, filepath.Join(dir, "node.crt"),
		now.AddDate(0, 0, -75), now.AddDate(0, 0, 25),
		[]string{"host.example.com"})

	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	d := r.decide(cert, discardLogger())
	if !d.fetch {
		t.Errorf("day 75 of 100-day cert with threshold 0.25 should fetch (inclusive): %s", d.reason)
	}
}

func TestDecide_ExpiredCertFetches(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	writePEMCert(t, filepath.Join(dir, "node.crt"),
		now.AddDate(0, 0, -100), now.AddDate(0, 0, -1),
		[]string{"host.example.com"})

	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	d := r.decide(cert, discardLogger())
	if !d.fetch {
		t.Errorf("expired cert should fetch, got skip: %s", d.reason)
	}
}

func TestDecide_ForceAlwaysFetches(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	writePEMCert(t, filepath.Join(dir, "node.crt"),
		now.AddDate(0, 0, -1), now.AddDate(0, 0, 99),
		[]string{"host.example.com"})

	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25, Force: true}, now)
	d := r.decide(cert, discardLogger())
	if !d.fetch || d.reason != "-force" {
		t.Errorf("force should fetch with reason -force, got fetch=%v reason=%q", d.fetch, d.reason)
	}
}

func TestDecide_CorruptCertFetches(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "node.crt"), []byte("not a PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, time.Now())
	if d := r.decide(cert, discardLogger()); !d.fetch {
		t.Errorf("corrupt cert should fetch, got skip: %s", d.reason)
	}
}

func TestDecide_LEAltNamesChangeFetchesEvenWhenFresh(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	// Existing leaf has SANs [fqdn, db0, db1]. Config now wants
	// [fqdn, db0, db1, db2] — TTL is fresh but SANs differ.
	writePEMCert(t, filepath.Join(dir, "tls.crt"),
		now.AddDate(0, 0, -1), now.AddDate(0, 0, 99),
		[]string{"db.example.com", "db0.example.com", "db1.example.com"})

	cert := config.CertConfig{
		Source:      config.SourceLetsencrypt,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "tls.crt", Key: "tls.key", CA: "ca.crt"},
		LEPath:      "letsencrypt/certs/dns-01/home/cloudflare/db.example.com",
		AltNames:    []string{"db0.example.com", "db1.example.com", "db2.example.com"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	d := r.decide(cert, discardLogger())
	if !d.fetch || d.reason != "alt_names changed" {
		t.Errorf("LE alt_names change should fetch, got fetch=%v reason=%q", d.fetch, d.reason)
	}
}

func TestDecide_LEMatchingAltNamesSkips(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	writePEMCert(t, filepath.Join(dir, "tls.crt"),
		now.AddDate(0, 0, -1), now.AddDate(0, 0, 99),
		// Deliberately out-of-order to confirm the comparison is
		// order-insensitive.
		[]string{"db.example.com", "db1.example.com", "db0.example.com"})

	cert := config.CertConfig{
		Source:      config.SourceLetsencrypt,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "tls.crt", Key: "tls.key", CA: "ca.crt"},
		LEPath:      "letsencrypt/certs/dns-01/home/cloudflare/db.example.com",
		AltNames:    []string{"db0.example.com", "db1.example.com"},
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	if d := r.decide(cert, discardLogger()); d.fetch {
		t.Errorf("matching alt_names should skip, got fetch: %s", d.reason)
	}
}

func TestDecide_PKIAltNamesChangeNotAutoDetected(t *testing.T) {
	// PKI does NOT auto-detect SAN drift; -force is the documented
	// way to push such a change. This test pins that behavior.
	dir := t.TempDir()
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	writePEMCert(t, filepath.Join(dir, "node.crt"),
		now.AddDate(0, 0, -1), now.AddDate(0, 0, 99),
		[]string{"host.example.com"})

	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
		CommonName:  "host.example.com",
		AltNames:    []string{"other.example.com"}, // differs from on-disk
	}
	r := newDecideRenewer(t, Options{ThresholdFraction: 0.25}, now)
	if d := r.decide(cert, discardLogger()); d.fetch {
		t.Errorf("PKI SAN change should NOT trigger auto-fetch (use -force), got: %s", d.reason)
	}
}

// ─────────────────────────────────────────────────────────────────
// Run-level tests — exercise processCert end-to-end with a fake
// source and the real writer.

func newRunRenewer(t *testing.T, src *fakeSource, opts Options) *Renewer {
	t.Helper()
	return New(&fakeSources{src: src}, writer.New(discardLogger()), reload.New(discardLogger()), discardLogger(), opts)
}

func TestRun_FetchAndWriteSucceeds(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSource{material: fakeFetchMaterial(t, []string{"host.example.com"})}
	r := newRunRenewer(t, src, Options{ThresholdFraction: 0.25})

	failures := r.Run(context.Background(), []config.CertConfig{{
		Name:        "test",
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}})
	if failures != 0 {
		t.Errorf("failures: got %d, want 0", failures)
	}
	if src.calls.Load() != 1 {
		t.Errorf("Fetch calls: got %d, want 1", src.calls.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "node.crt")); err != nil {
		t.Errorf("expected node.crt written: %v", err)
	}
}

func TestRun_DryRunSkipsFetchAndWrite(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSource{material: fakeFetchMaterial(t, []string{"host.example.com"})}
	r := newRunRenewer(t, src, Options{ThresholdFraction: 0.25, DryRun: true})

	failures := r.Run(context.Background(), []config.CertConfig{{
		Name:        "test",
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
		Files:       &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}})
	if failures != 0 {
		t.Errorf("failures: got %d, want 0", failures)
	}
	if src.calls.Load() != 0 {
		t.Errorf("dry-run should not Fetch, got %d calls", src.calls.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "node.crt")); !os.IsNotExist(err) {
		t.Errorf("dry-run should not write files: %v", err)
	}
}

func TestRun_ReloadFiresOnChangeAndCountsFailureOnNonZeroExit(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSource{material: fakeFetchMaterial(t, []string{"host.example.com"})}
	r := newRunRenewer(t, src, Options{ThresholdFraction: 0.25})

	failures := r.Run(context.Background(), []config.CertConfig{{
		Name:          "test",
		Source:        config.SourcePKI,
		Destination:   dir,
		Format:        config.FormatSplit,
		Owner:         testOwner(t),
		Mode:          "0600",
		ReloadCommand: []string{"sh", "-c", "exit 7"}, // simulate a reload-script failure
		Files:         &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}})
	if failures != 1 {
		t.Errorf("reload exit 7 should count as failure, got %d failures", failures)
	}
	// Files should still be on disk — reload failure happens after
	// the write succeeded.
	if _, err := os.Stat(filepath.Join(dir, "node.crt")); err != nil {
		t.Errorf("cert should be written before reload runs: %v", err)
	}
}

func TestRun_ReloadSkippedWhenContentUnchanged(t *testing.T) {
	dir := t.TempDir()
	mat := fakeFetchMaterial(t, []string{"host.example.com"})
	src := &fakeSource{material: mat}
	r := newRunRenewer(t, src, Options{ThresholdFraction: 0.25, Force: true})

	reloadDir := t.TempDir()
	reloadSentinel := filepath.Join(reloadDir, "reloaded")

	cert := config.CertConfig{
		Name:          "test",
		Source:        config.SourcePKI,
		Destination:   dir,
		Format:        config.FormatSplit,
		Owner:         testOwner(t),
		Mode:          "0600",
		ReloadCommand: []string{"touch", reloadSentinel},
		Files:         &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"},
	}
	// First run: fetch, write, reload (Changed=true).
	if f := r.Run(context.Background(), []config.CertConfig{cert}); f != 0 {
		t.Fatalf("first run failures: %d", f)
	}
	if _, err := os.Stat(reloadSentinel); err != nil {
		t.Fatalf("first run should have reloaded: %v", err)
	}
	if err := os.Remove(reloadSentinel); err != nil {
		t.Fatal(err)
	}

	// Second run: same material → Changed=false → no reload.
	if f := r.Run(context.Background(), []config.CertConfig{cert}); f != 0 {
		t.Fatalf("second run failures: %d", f)
	}
	if _, err := os.Stat(reloadSentinel); !os.IsNotExist(err) {
		t.Errorf("second run should NOT have reloaded (content unchanged): %v", err)
	}
}

func TestRun_PerCertFailureDoesNotAbortLoop(t *testing.T) {
	good := t.TempDir()
	failing := &fakeSource{err: errAlwaysFails{}}
	successful := &fakeSource{material: fakeFetchMaterial(t, []string{"host.example.com"})}

	// Dispatch: pki cert fails, letsencrypt cert succeeds.
	srcs := &fakeSources{by: func(name string) source.Source {
		if name == config.SourcePKI {
			return failing
		}
		return successful
	}}
	r := New(srcs, writer.New(discardLogger()), reload.New(discardLogger()), discardLogger(), Options{ThresholdFraction: 0.25, Force: true})

	pkiFiles := &config.FilesOverride{Cert: "node.crt", Key: "node.key", CA: "ca.crt"}
	leFiles := &config.FilesOverride{Cert: "tls.crt", Key: "tls.key", CA: "ca.crt"}
	failures := r.Run(context.Background(), []config.CertConfig{
		{Name: "a", Source: config.SourcePKI, Destination: t.TempDir(), Format: config.FormatSplit, Owner: testOwner(t), Mode: "0600", Files: pkiFiles},
		{Name: "b", Source: config.SourceLetsencrypt, Destination: good, Format: config.FormatSplit, Owner: testOwner(t), Mode: "0600", Files: leFiles},
	})
	if failures != 1 {
		t.Errorf("expected 1 failure (the failing cert), got %d", failures)
	}
	if successful.calls.Load() != 1 {
		t.Errorf("loop should have processed the second cert; got %d calls", successful.calls.Load())
	}
	if _, err := os.Stat(filepath.Join(good, "tls.crt")); err != nil {
		t.Errorf("successful cert should be written: %v", err)
	}
}

type errAlwaysFails struct{}

func (errAlwaysFails) Error() string { return "always fails" }
