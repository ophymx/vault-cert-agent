// Package renewer orchestrates the per-cert decide → fetch → write →
// reload loop. It is the single owner of the renewal decision; the
// source, writer, and reload runner just execute its orders.
package renewer

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/source"
	"github.com/ophymx/vault-cert-agent/internal/writer"
)

// Options configures a Renewer.
type Options struct {
	// ThresholdFraction is the floor on remaining lifetime, taken
	// from the resolved config. Fetch fires when the on-disk leaf's
	// remaining_fraction <= ThresholdFraction.
	ThresholdFraction float64
	// Force ignores the TTL threshold and fetches every cert.
	Force bool
	// DryRun reports what would happen without fetching or writing.
	DryRun bool
}

// Sources resolves a cert config's `source` name to a Source impl.
// *source.Registry satisfies this. Defining the interface here keeps
// the production type concrete while letting tests inject fakes.
type Sources interface {
	For(name string) (source.Source, error)
}

// Reloader triggers the per-cert reload action after a successful
// write. *reload.Manager satisfies this; the interface lets the
// renewer stay independent of which transport was configured.
type Reloader interface {
	Reload(ctx context.Context, cert config.CertConfig) error
}

// Renewer ties source resolution and a writer together with the
// renewal decision logic.
type Renewer struct {
	sources  Sources
	writer   *writer.Writer
	reloader Reloader
	logger   *slog.Logger
	opts     Options
	now      func() time.Time
}

// New returns a Renewer. The clock is wall-clock; tests inject one
// via SetClock. A nil reloader is treated as "no-op" — the renewer
// will write certs but never trigger reloads, which is useful for
// dry-run-adjacent tests.
func New(sources Sources, w *writer.Writer, reloader Reloader, logger *slog.Logger, opts Options) *Renewer {
	return &Renewer{
		sources:  sources,
		writer:   w,
		reloader: reloader,
		logger:   logger,
		opts:     opts,
		now:      time.Now,
	}
}

// SetClock overrides the wall-clock source. For tests only.
func (r *Renewer) SetClock(now func() time.Time) { r.now = now }

// Run processes every cert in order. It returns the number of certs
// that failed; the caller maps non-zero to exit code 2. A single cert
// failing never aborts the loop — partial success is normal.
func (r *Renewer) Run(ctx context.Context, certs []config.CertConfig) int {
	var failures int
	for _, cert := range certs {
		if err := r.processCert(ctx, cert); err != nil {
			failures++
			r.logger.Error("cert failed", "cert", cert.Name, "err", err)
		}
	}
	return failures
}

func (r *Renewer) processCert(ctx context.Context, cert config.CertConfig) error {
	log := r.logger.With("cert", cert.Name)

	src, err := r.sources.For(cert.Source)
	if err != nil {
		return err
	}

	d := r.decide(cert, log)
	if !d.fetch {
		log.Info("skip", "reason", d.reason)
		return nil
	}
	log.Info("renew", "reason", d.reason)

	if r.opts.DryRun {
		log.Info("dry-run; would fetch and write")
		return nil
	}

	material, err := src.Fetch(ctx, cert)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}

	result, err := r.writer.Write(material, cert)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	log.Info("wrote", "changed", result.Changed, "paths", result.Paths)

	if result.Changed && r.reloader != nil {
		if err := r.reloader.Reload(ctx, cert); err != nil {
			// Cert is on disk but the consumer didn't reload: count
			// this toward partial-failure exit so a human notices.
			return fmt.Errorf("reload: %w", err)
		}
	}
	return nil
}

type decision struct {
	fetch  bool
	reason string
}

func (r *Renewer) decide(cert config.CertConfig, log *slog.Logger) decision {
	if r.opts.Force {
		return decision{fetch: true, reason: "-force"}
	}

	// Every declared split slot must exist on disk with a shape that
	// matches the slot's semantics. Catches the cases the leaf-TTL
	// check on its own would skip indefinitely: a newly-declared slot
	// whose file doesn't exist yet, or a slot whose filename was
	// repurposed (cert <-> fullchain) so the on-disk shape is now
	// wrong for the configured intent.
	if d := auditOnDiskFiles(cert); d.fetch {
		return d
	}

	leafPath := writer.ResolveLeafPath(cert)
	if leafPath == "" {
		// No leaf-bearing slot configured (e.g. files block declares
		// only key/ca). Nothing to TTL-evaluate, so we always fetch.
		return decision{fetch: true, reason: "no leaf-bearing file configured"}
	}
	leaf, err := loadLeaf(leafPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return decision{fetch: true, reason: "no existing cert at " + leafPath}
	case err != nil:
		log.Warn("existing cert unreadable; will refetch", "path", leafPath, "err", err)
		return decision{fetch: true, reason: "existing cert unparseable"}
	}

	now := r.now()
	total := leaf.NotAfter.Sub(leaf.NotBefore)
	remaining := leaf.NotAfter.Sub(now)
	if total <= 0 || remaining <= 0 {
		return decision{fetch: true, reason: "expired or invalid validity window"}
	}
	fraction := float64(remaining) / float64(total)
	if fraction <= r.opts.ThresholdFraction {
		return decision{
			fetch:  true,
			reason: fmt.Sprintf("remaining %.0f%% <= threshold %.0f%%", fraction*100, r.opts.ThresholdFraction*100),
		}
	}

	// LE-specific: the renewer must catch alt_names changes the TTL
	// path would otherwise hide. PKI doesn't need this — operators
	// can refresh PKI alt_names changes via -force or wait for TTL.
	if cert.Source == config.SourceLetsencrypt && altNamesDiffer(cert, leaf) {
		return decision{fetch: true, reason: "alt_names changed"}
	}

	return decision{
		fetch:  false,
		reason: fmt.Sprintf("remaining %.0f%% > threshold %.0f%%", fraction*100, r.opts.ThresholdFraction*100),
	}
}

// loadLeaf reads the first PEM block from path and parses it as an
// X.509 certificate. Works for split (leaf-alone file) and combined
// (leaf + chain + key concatenated) — the first block is always the
// leaf in both layouts.
func loadLeaf(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("first PEM block is %s, want CERTIFICATE", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// auditOnDiskFiles verifies each declared split slot has a file on
// disk whose shape matches the slot's semantics:
//
//	cert      — file exists, exactly one CERTIFICATE PEM block.
//	fullchain — file exists, at least two CERTIFICATE PEM blocks.
//	key, ca   — file exists.
//
// Returns fetch=true with a per-slot reason on the first failure.
// A missing file or wrong shape catches operator config changes
// (adding a slot, swapping cert <-> fullchain on the same filename)
// that the leaf TTL check on its own would skip indefinitely.
// Combined format is a single-file layout that owns its own
// existence check downstream; the audit is split-only.
func auditOnDiskFiles(cert config.CertConfig) decision {
	if cert.Format != config.FormatSplit || cert.Files == nil {
		return decision{}
	}
	f := cert.Files
	slots := []struct {
		name, filename string
		check          func(path string) (ok bool, why string)
	}{
		{"cert", f.Cert, checkLeafOnly},
		{"key", f.Key, checkExists},
		{"ca", f.CA, checkExists},
		{"fullchain", f.Fullchain, checkLeafPlusChain},
	}
	for _, s := range slots {
		if s.filename == "" {
			continue
		}
		path := filepath.Join(cert.Destination, s.filename)
		if ok, why := s.check(path); !ok {
			return decision{fetch: true, reason: s.name + " slot: " + why}
		}
	}
	return decision{}
}

func checkExists(path string) (bool, string) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, "missing file " + path
		}
		return false, "stat " + path + ": " + err.Error()
	}
	return true, ""
}

// checkLeafOnly verifies path is a single CERTIFICATE PEM block —
// the shape the writer emits for the cert slot.
func checkLeafOnly(path string) (bool, string) {
	raw, err := readForAudit(path)
	if err != nil {
		return false, err.Error()
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, path + " has no leaf CERTIFICATE block"
	}
	for len(rest) > 0 {
		var next *pem.Block
		next, rest = pem.Decode(rest)
		if next == nil {
			break
		}
		if next.Type == "CERTIFICATE" {
			return false, path + " contains a chain (expected leaf only)"
		}
	}
	return true, ""
}

// checkLeafPlusChain verifies path contains at least two CERTIFICATE
// PEM blocks — the shape the writer emits for the fullchain slot.
func checkLeafPlusChain(path string) (bool, string) {
	raw, err := readForAudit(path)
	if err != nil {
		return false, err.Error()
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, path + " has no leaf CERTIFICATE block"
	}
	for len(rest) > 0 {
		var next *pem.Block
		next, rest = pem.Decode(rest)
		if next == nil {
			break
		}
		if next.Type == "CERTIFICATE" {
			return true, ""
		}
	}
	return false, path + " missing chain (only one CERTIFICATE block)"
}

// readForAudit normalises the "missing file" error message so audit
// callers don't each re-format os.PathError text.
func readForAudit(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("missing file %s", path)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}

// altNamesDiffer reports whether the on-disk leaf's DNSNames don't
// match the union of [fqdn, ...cert.AltNames] for an LE cert. The
// fqdn is the last segment of le_path — matching how the LE plugin
// derives it on the server side.
func altNamesDiffer(cert config.CertConfig, leaf *x509.Certificate) bool {
	fqdn := lePathFqdn(cert.LEPath)
	expected := make([]string, 0, 1+len(cert.AltNames))
	if fqdn != "" {
		expected = append(expected, fqdn)
	}
	expected = append(expected, cert.AltNames...)
	return !slicesEqualUnordered(expected, leaf.DNSNames)
}

func lePathFqdn(lePath string) string {
	trimmed := strings.Trim(lePath, "/")
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	return parts[len(parts)-1]
}

func slicesEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := slices.Clone(a)
	bCopy := slices.Clone(b)
	slices.Sort(aCopy)
	slices.Sort(bCopy)
	return slices.Equal(aCopy, bCopy)
}
