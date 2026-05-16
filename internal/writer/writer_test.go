package writer

import (
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/source"
)

// testOwner returns "username:groupname" for the current process so
// chown() succeeds without root in tests.
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

func newWriter() *Writer {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func sampleMaterial() *source.Material {
	return &source.Material{
		Cert: []byte("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"),
		Key:  []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"),
		CA: []byte(
			"-----BEGIN CERTIFICATE-----\nint\n-----END CERTIFICATE-----\n" +
				"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n",
		),
	}
}

func TestWrite_Split_FirstRunCreatesThreeFiles(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "tls")
	m := sampleMaterial()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dest,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0640",
	}

	res, err := newWriter().Write(m, cert)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !res.Changed {
		t.Errorf("Changed: got false, want true (first run)")
	}
	wantPaths := []string{
		filepath.Join(dest, "node.crt"),
		filepath.Join(dest, "node.key"),
		filepath.Join(dest, "ca.crt"),
	}
	if len(res.Paths) != 3 {
		t.Fatalf("Paths: got %v, want 3 entries", res.Paths)
	}
	for i, p := range wantPaths {
		if res.Paths[i] != p {
			t.Errorf("Paths[%d]: got %q, want %q", i, res.Paths[i], p)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("stat %s: %v", p, err)
			continue
		}
		if info.Mode().Perm() != 0o640 {
			t.Errorf("%s mode: got %o, want 0640", p, info.Mode().Perm())
		}
	}
	leaf, _ := os.ReadFile(wantPaths[0])
	if !strings.Contains(string(leaf), "leaf") {
		t.Errorf("leaf content: %q", leaf)
	}
}

func TestWrite_Split_NoChangeButFixesStaleMode(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "tls")
	m := sampleMaterial()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dest,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
	}
	w := newWriter()

	if _, err := w.Write(m, cert); err != nil {
		t.Fatal(err)
	}

	// Simulate drift: someone chmods the cert file to 0644.
	driftedPath := filepath.Join(dest, "node.crt")
	if err := os.Chmod(driftedPath, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := w.Write(m, cert)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Errorf("Changed: got true, want false (content unchanged)")
	}
	info, err := os.Stat(driftedPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms not re-enforced: got %o, want 0600 — this is the old vault-pki-renew bug", info.Mode().Perm())
	}
}

func TestWrite_Split_ContentChangeReportsChanged(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "tls")
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dest,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
	}
	w := newWriter()
	if _, err := w.Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}

	updated := &source.Material{
		Cert: []byte("-----BEGIN CERTIFICATE-----\nleaf-v2\n-----END CERTIFICATE-----\n"),
		Key:  []byte("-----BEGIN PRIVATE KEY-----\nkey-v2\n-----END PRIVATE KEY-----\n"),
		CA:   []byte("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n"),
	}
	res, err := w.Write(updated, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Errorf("Changed: got false, want true (content change)")
	}
	got, _ := os.ReadFile(filepath.Join(dest, "node.crt"))
	if !strings.Contains(string(got), "leaf-v2") {
		t.Errorf("leaf not updated: %q", got)
	}
}

func TestWrite_Combined_SingleFileOrderedCertCAKey(t *testing.T) {
	dir := t.TempDir()
	destFile := filepath.Join(dir, "haproxy.pem")
	m := sampleMaterial()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: destFile,
		Format:      config.FormatCombined,
		Owner:       testOwner(t),
		Mode:        "0640",
	}

	res, err := newWriter().Write(m, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Error("expected Changed=true on first run")
	}
	if len(res.Paths) != 1 || res.Paths[0] != destFile {
		t.Errorf("Paths: got %v", res.Paths)
	}
	got, err := os.ReadFile(destFile)
	if err != nil {
		t.Fatal(err)
	}
	// Order must be leaf, then chain, then key — what HAProxy expects.
	leafIdx := strings.Index(string(got), "leaf")
	intIdx := strings.Index(string(got), "int")
	rootIdx := strings.Index(string(got), "root")
	keyIdx := strings.Index(string(got), "key")
	if !(leafIdx >= 0 && leafIdx < intIdx && intIdx < rootIdx && rootIdx < keyIdx) {
		t.Errorf("wrong order: leaf=%d int=%d root=%d key=%d",
			leafIdx, intIdx, rootIdx, keyIdx)
	}
}

func TestWrite_Combined_BundleOrderRespected(t *testing.T) {
	// All six permutations should produce the configured slot order.
	cases := []struct {
		order string
		want  []string // substring sequence
	}{
		{config.BundleOrderCertChainKey, []string{"leaf", "int", "root", "key"}},
		{config.BundleOrderCertKeyChain, []string{"leaf", "key", "int", "root"}},
		{config.BundleOrderKeyCertChain, []string{"key", "leaf", "int", "root"}},
		{config.BundleOrderKeyChainCert, []string{"key", "int", "root", "leaf"}},
		{config.BundleOrderChainCertKey, []string{"int", "root", "leaf", "key"}},
		{config.BundleOrderChainKeyCert, []string{"int", "root", "key", "leaf"}},
	}
	for _, tc := range cases {
		t.Run(tc.order, func(t *testing.T) {
			dir := t.TempDir()
			destFile := filepath.Join(dir, "bundle.pem")
			cert := config.CertConfig{
				Source:      config.SourcePKI,
				Destination: destFile,
				Format:      config.FormatCombined,
				BundleOrder: tc.order,
				Owner:       testOwner(t),
				Mode:        "0600",
			}
			if _, err := newWriter().Write(sampleMaterial(), cert); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(destFile)
			if err != nil {
				t.Fatal(err)
			}
			lastIdx := -1
			for _, marker := range tc.want {
				idx := strings.Index(string(got), marker)
				if idx <= lastIdx {
					t.Errorf("marker %q not in expected position (idx=%d, prev=%d) for order %q\nfile: %q",
						marker, idx, lastIdx, tc.order, got)
				}
				lastIdx = idx
			}
		})
	}
}

func TestWrite_Combined_CreatesParentDir(t *testing.T) {
	// First-run case for HAProxy-style combined certs: the package
	// installer typically owns /etc/<consumer>/ but not necessarily
	// every intermediate. The writer must create the parent itself.
	base := t.TempDir()
	destFile := filepath.Join(base, "newdir", "haproxy.pem")
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: destFile,
		Format:      config.FormatCombined,
		Owner:       testOwner(t),
		Mode:        "0640",
	}
	if _, err := newWriter().Write(sampleMaterial(), cert); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(destFile); err != nil {
		t.Errorf("expected combined file at %s: %v", destFile, err)
	}
}

func TestWrite_Split_FilesOverrideBeatsDefaults(t *testing.T) {
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
		Files: &config.FilesOverride{
			Cert: "server.pem",
			Key:  "server.key",
			// CA left empty → falls back to default "ca.crt".
		},
	}

	if _, err := newWriter().Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server.pem", "server.key", "ca.crt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}
	// And the default names must NOT exist alongside.
	if _, err := os.Stat(filepath.Join(dir, "node.crt")); !os.IsNotExist(err) {
		t.Errorf("node.crt should not exist when override is set")
	}
}

func TestWrite_Split_LetsencryptUsesTLSDefaults(t *testing.T) {
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourceLetsencrypt,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
	}
	if _, err := newWriter().Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}
}

func TestResolveLeafPath(t *testing.T) {
	cases := []struct {
		name string
		cert config.CertConfig
		want string
	}{
		{
			name: "split pki default",
			cert: config.CertConfig{Source: config.SourcePKI, Format: config.FormatSplit, Destination: "/tls"},
			want: "/tls/node.crt",
		},
		{
			name: "split le default",
			cert: config.CertConfig{Source: config.SourceLetsencrypt, Format: config.FormatSplit, Destination: "/tls"},
			want: "/tls/tls.crt",
		},
		{
			name: "split override",
			cert: config.CertConfig{
				Source: config.SourcePKI, Format: config.FormatSplit, Destination: "/tls",
				Files: &config.FilesOverride{Cert: "server.pem"},
			},
			want: "/tls/server.pem",
		},
		{
			name: "combined",
			cert: config.CertConfig{Format: config.FormatCombined, Destination: "/etc/haproxy/cert.pem"},
			want: "/etc/haproxy/cert.pem",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveLeafPath(tc.cert); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWrite_AtomicWriteLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
	}
	if _, err := newWriter().Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".vault-cert-agent-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}
