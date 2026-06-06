package writer

import (
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"slices"
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

// pkiFiles is the conventional set of split filenames for a PKI cert
// in tests — leaf, key, and chain together. Mirrors what an operator
// would put in HCL after the explicit-declaration switch.
func pkiFiles() *config.FilesOverride {
	return &config.FilesOverride{
		Cert: "node.crt",
		Key:  "node.key",
		CA:   "ca.crt",
	}
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
		Files:       pkiFiles(),
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

func TestWrite_Split_KeyModeOverrideTightensKeyOnly(t *testing.T) {
	// The key file gets the tighter 0600; cert and ca keep the
	// cert-level 0644. Mirrors the conventional postgres setup.
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0644",
		KeyMode:     "0600",
		Files:       pkiFiles(),
	}
	if _, err := newWriter().Write(sampleMaterial(), cert); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(dir, "node.crt"): 0o644,
		filepath.Join(dir, "ca.crt"):   0o644,
		filepath.Join(dir, "node.key"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("stat %s: %v", path, err)
			continue
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode: got %o, want %o", path, info.Mode().Perm(), want)
		}
	}
}

func TestWrite_Split_KeyModeOverrideAppliedOnUnchangedRun(t *testing.T) {
	// The perm-on-unchanged path must respect the key override too —
	// otherwise drift correction would silently widen the key.
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0644",
		KeyMode:     "0600",
		Files:       pkiFiles(),
	}
	w := newWriter()
	if _, err := w.Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "node.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key mode not re-enforced to override: got %o, want 0600", info.Mode().Perm())
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
		Files:       pkiFiles(),
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
		Files:       pkiFiles(),
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

func TestWrite_Split_CustomFilenamesEmitOnlyTheNamedSlots(t *testing.T) {
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
			CA:   "chain.pem",
		},
	}

	if _, err := newWriter().Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server.pem", "server.key", "chain.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}
	// No source-derived defaults: legacy names must NOT appear.
	for _, ghost := range []string{"node.crt", "node.key", "ca.crt", "tls.crt", "tls.key"} {
		if _, err := os.Stat(filepath.Join(dir, ghost)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist under explicit-declaration model", ghost)
		}
	}
}

func TestWrite_Split_OnlyDeclaredSlotsAreWritten(t *testing.T) {
	// Subset declaration: just fullchain + key. cert and ca must not
	// be emitted (no leaf-only file, no chain-only file).
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
		Files: &config.FilesOverride{
			Key:       "tls.key",
			Fullchain: "fullchain.pem",
		},
	}
	res, err := newWriter().Write(sampleMaterial(), cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) != 2 {
		t.Errorf("expected 2 written paths, got %d (%v)", len(res.Paths), res.Paths)
	}
	for _, name := range []string{"tls.key", "fullchain.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}
	for _, ghost := range []string{"node.crt", "ca.crt", "tls.crt"} {
		if _, err := os.Stat(filepath.Join(dir, ghost)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist when not declared", ghost)
		}
	}
}

func TestWrite_Split_FullchainOptInWritesLeafPlusChain(t *testing.T) {
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0640",
		Files:       &config.FilesOverride{Fullchain: "fullchain.pem"},
	}
	res, err := newWriter().Write(sampleMaterial(), cert)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	fullchainPath := filepath.Join(dir, "fullchain.pem")
	if !slices.Contains(res.Paths, fullchainPath) {
		t.Errorf("Paths missing fullchain entry: %v", res.Paths)
	}
	got, err := os.ReadFile(fullchainPath)
	if err != nil {
		t.Fatalf("read fullchain: %v", err)
	}
	leafIdx := strings.Index(string(got), "leaf")
	intIdx := strings.Index(string(got), "int")
	rootIdx := strings.Index(string(got), "root")
	if !(leafIdx >= 0 && leafIdx < intIdx && intIdx < rootIdx) {
		t.Errorf("wrong fullchain order: leaf=%d int=%d root=%d\nfile: %q",
			leafIdx, intIdx, rootIdx, got)
	}
	if strings.Contains(string(got), "PRIVATE KEY") {
		t.Errorf("fullchain must not include the private key: %q", got)
	}
	info, err := os.Stat(fullchainPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("fullchain mode: got %o, want 0640", info.Mode().Perm())
	}
}

func TestWrite_Split_NoFullchainWhenUndeclared(t *testing.T) {
	// A files block that names cert/key/ca but not fullchain must not
	// produce a fullchain file.
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
		Files:       pkiFiles(),
	}
	if _, err := newWriter().Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fullchain.pem", "fullchain.crt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist without opt-in (err=%v)", name, err)
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
			name: "split cert slot",
			cert: config.CertConfig{
				Source: config.SourcePKI, Format: config.FormatSplit, Destination: "/tls",
				Files: &config.FilesOverride{Cert: "server.pem", Key: "server.key"},
			},
			want: "/tls/server.pem",
		},
		{
			name: "split falls back to fullchain when cert absent",
			cert: config.CertConfig{
				Source: config.SourcePKI, Format: config.FormatSplit, Destination: "/tls",
				Files: &config.FilesOverride{Key: "tls.key", Fullchain: "fullchain.pem"},
			},
			want: "/tls/fullchain.pem",
		},
		{
			name: "split with neither cert nor fullchain returns empty",
			cert: config.CertConfig{
				Source: config.SourcePKI, Format: config.FormatSplit, Destination: "/tls",
				Files: &config.FilesOverride{Key: "tls.key", CA: "ca.crt"},
			},
			want: "",
		},
		{
			name: "split with nil Files returns empty",
			cert: config.CertConfig{
				Source: config.SourcePKI, Format: config.FormatSplit, Destination: "/tls",
			},
			want: "",
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

func TestWrite_Split_RefusesSymlinkAtDestination(t *testing.T) {
	// If a low-priv consumer can plant a symlink at the leaf path
	// pointing at /etc/shadow (or whatever), the agent must NOT chown
	// the target. enforcePerms + the read path both refuse via O_NOFOLLOW.
	dir := t.TempDir()
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: dir,
		Format:      config.FormatSplit,
		Owner:       testOwner(t),
		Mode:        "0600",
		Files:       pkiFiles(),
	}
	w := newWriter()
	if _, err := w.Write(sampleMaterial(), cert); err != nil {
		t.Fatal(err)
	}
	// Swap one of the files for a symlink to an unrelated target.
	leaf := filepath.Join(dir, "node.crt")
	decoy := filepath.Join(dir, "decoy")
	if err := os.WriteFile(decoy, []byte("decoy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(leaf); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, leaf); err != nil {
		t.Fatal(err)
	}

	// Second run must refuse the symlinked path. Whether it errors via
	// the read path or the enforce path, what matters is that Write
	// returns an error and decoy keeps its 0644 mode.
	if _, err := w.Write(sampleMaterial(), cert); err == nil {
		t.Fatal("expected error when destination is a symlink")
	}
	info, err := os.Lstat(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("decoy mode mutated: got %o, want 0644 (symlink should have blocked chmod)", info.Mode().Perm())
	}
}

func TestWrite_Combined_RefusesSymlinkAtDestination(t *testing.T) {
	dir := t.TempDir()
	destFile := filepath.Join(dir, "bundle.pem")
	decoy := filepath.Join(dir, "decoy")
	if err := os.WriteFile(decoy, []byte("decoy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, destFile); err != nil {
		t.Fatal(err)
	}
	cert := config.CertConfig{
		Source:      config.SourcePKI,
		Destination: destFile,
		Format:      config.FormatCombined,
		Owner:       testOwner(t),
		Mode:        "0600",
	}
	if _, err := newWriter().Write(sampleMaterial(), cert); err == nil {
		t.Fatal("expected error when combined destination is a symlink")
	}
	info, err := os.Lstat(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("decoy mode mutated: got %o, want 0644", info.Mode().Perm())
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
		Files:       pkiFiles(),
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
