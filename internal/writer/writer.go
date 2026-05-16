// Package writer commits fetched cert material to disk atomically
// and enforces mode/owner on the resulting files.
package writer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/source"
)

// Writer commits Material to disk. One per process is sufficient;
// state is per-call.
type Writer struct {
	logger *slog.Logger
}

// New returns a Writer that emits progress to the given logger.
func New(logger *slog.Logger) *Writer { return &Writer{logger: logger} }

// Result describes what Write did.
type Result struct {
	// Changed is true when any of the resulting files had its content
	// modified by this call. Used by the renewer to decide whether to
	// run reload_command.
	Changed bool
	// Paths is every final on-disk path Write touched, in the order
	// they were processed.
	Paths []string
}

// Write commits material to disk per cert.Format, then re-enforces
// mode and owner on every resulting file — including when the content
// was already up to date.
func (w *Writer) Write(material *source.Material, cert config.CertConfig) (*Result, error) {
	mode, uid, gid, err := resolvePerms(cert)
	if err != nil {
		return nil, err
	}

	switch cert.Format {
	case config.FormatSplit:
		return w.writeSplit(material, cert, mode, uid, gid)
	case config.FormatCombined:
		return w.writeCombined(material, cert, mode, uid, gid)
	default:
		return nil, fmt.Errorf("unknown format %q", cert.Format)
	}
}

// ResolveLeafPath returns the on-disk path where the leaf cert lives
// for the given cert config. The renewer uses this to compute the
// existing cert's remaining lifetime before deciding to fetch.
func ResolveLeafPath(cert config.CertConfig) string {
	switch cert.Format {
	case config.FormatSplit:
		certPath, _, _ := resolveSplitPaths(cert)
		return certPath
	case config.FormatCombined:
		return cert.Destination
	}
	return ""
}

func (w *Writer) writeSplit(m *source.Material, cert config.CertConfig, mode os.FileMode, uid, gid int) (*Result, error) {
	certPath, keyPath, caPath := resolveSplitPaths(cert)
	if err := os.MkdirAll(cert.Destination, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", cert.Destination, err)
	}
	out := &Result{}
	for _, f := range []struct {
		path    string
		content []byte
	}{
		{certPath, m.Cert},
		{keyPath, m.Key},
		{caPath, m.CA},
	} {
		changed, err := w.commitFile(f.path, f.content, mode, uid, gid)
		if err != nil {
			return nil, err
		}
		out.Changed = out.Changed || changed
		out.Paths = append(out.Paths, f.path)
	}
	return out, nil
}

func (w *Writer) writeCombined(m *source.Material, cert config.CertConfig, mode os.FileMode, uid, gid int) (*Result, error) {
	// In combined mode cert.Destination is a file path (HAProxy
	// convention), so the parent directory is what may not exist yet.
	parent := filepath.Dir(cert.Destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", parent, err)
	}
	parts, err := bundleParts(cert.BundleOrder, m)
	if err != nil {
		return nil, err
	}
	content := make([]byte, 0, len(m.Cert)+len(m.CA)+len(m.Key))
	for _, p := range parts {
		content = append(content, p...)
	}

	changed, err := w.commitFile(cert.Destination, content, mode, uid, gid)
	if err != nil {
		return nil, err
	}
	return &Result{Changed: changed, Paths: []string{cert.Destination}}, nil
}

// bundleParts returns the three PEM blobs in the order dictated by
// order. Empty order falls back to DefaultBundleOrder.
func bundleParts(order string, m *source.Material) ([][]byte, error) {
	if order == "" {
		order = config.DefaultBundleOrder
	}
	layout, ok := bundleLayouts[order]
	if !ok {
		return nil, fmt.Errorf("unknown bundle_order %q", order)
	}
	parts := make([][]byte, 3)
	for i, slot := range layout {
		switch slot {
		case slotCert:
			parts[i] = m.Cert
		case slotChain:
			parts[i] = m.CA
		case slotKey:
			parts[i] = m.Key
		}
	}
	return parts, nil
}

type bundleSlot int

const (
	slotCert bundleSlot = iota
	slotChain
	slotKey
)

var bundleLayouts = map[string][3]bundleSlot{
	config.BundleOrderCertChainKey: {slotCert, slotChain, slotKey},
	config.BundleOrderCertKeyChain: {slotCert, slotKey, slotChain},
	config.BundleOrderKeyCertChain: {slotKey, slotCert, slotChain},
	config.BundleOrderKeyChainCert: {slotKey, slotChain, slotCert},
	config.BundleOrderChainCertKey: {slotChain, slotCert, slotKey},
	config.BundleOrderChainKeyCert: {slotChain, slotKey, slotCert},
}

// commitFile writes content to path iff it differs from what's already
// there, and always re-enforces mode + owner. The perms-on-unchanged
// path is intentional: it fixes drift from prior runs where a config
// permission change didn't take effect because the cert content was
// still fresh (the vault-pki-renew bug from the bash days).
//
// Symlinks at path are refused. We run as root and chown to per-cert
// owners; if a consumer with write access to the destination directory
// swaps the file for a symlink we must not chmod/chown the target.
func (w *Writer) commitFile(path string, content []byte, mode os.FileMode, uid, gid int) (bool, error) {
	existing, err := readRegularFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// First-time write.
	case err != nil:
		return false, err
	case bytes.Equal(existing, content):
		w.logger.Debug("content unchanged, enforcing perms", "path", path)
		if err := enforcePerms(path, mode, uid, gid); err != nil {
			return false, err
		}
		return false, nil
	}

	w.logger.Debug("writing file", "path", path, "bytes", len(content))
	if err := atomicWrite(path, content, mode, uid, gid); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

// readRegularFile opens path with O_NOFOLLOW (so a symlinked path
// errors out instead of redirecting us) and verifies the inode is a
// regular file (no fifos, devices, sockets — same defensive posture).
// Returns os.ErrNotExist transparently for the first-write case.
func readRegularFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (mode %s)", path, info.Mode())
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return b, nil
}

// atomicWrite stages content at a temp file in the same directory,
// applies mode+owner against the open fd, then renames into place.
// Readers never see a partial or wrong-permissioned file. The fd-based
// chmod/chown ensures the perms land on the inode we just created
// rather than whatever path resolution might walk to.
func atomicWrite(path string, content []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".vault-cert-agent-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := f.Write(content); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := f.Chown(uid, gid); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// enforcePerms re-applies mode + owner on an existing file. O_NOFOLLOW
// + regular-file check keeps a symlink or fifo planted at path from
// redirecting the chmod/chown to an unrelated inode. Once the fd is
// open the inode is pinned, so there's no TOCTOU window between
// fchmod and fchown.
func enforcePerms(path string, mode os.FileMode, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (mode %s)", path, info.Mode())
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := f.Chown(uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

func resolvePerms(cert config.CertConfig) (os.FileMode, int, int, error) {
	mode, err := config.ParseMode(cert.Mode)
	if err != nil {
		return 0, 0, 0, err
	}
	userName, groupName, err := config.ParseOwner(cert.Owner)
	if err != nil {
		return 0, 0, 0, err
	}
	uid, gid, err := lookupOwner(userName, groupName)
	if err != nil {
		return 0, 0, 0, err
	}
	return mode, uid, gid, nil
}

func lookupOwner(userName, groupName string) (int, int, error) {
	u, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %q: %w", userName, err)
	}
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup group %q: %w", groupName, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q: %w", g.Gid, err)
	}
	return uid, gid, nil
}

// splitNames is the per-source default filename triple for the
// split-format layout. Operators can override any of the three via
// the per-cert `files` block; an empty override falls back to the
// default here.
type splitNames struct{ cert, key, ca string }

var splitDefaults = map[string]splitNames{
	config.SourcePKI:         {cert: "node.crt", key: "node.key", ca: "ca.crt"},
	config.SourceLetsencrypt: {cert: "tls.crt", key: "tls.key", ca: "ca.crt"},
}

func resolveSplitPaths(c config.CertConfig) (certPath, keyPath, caPath string) {
	n := splitDefaults[c.Source]
	if c.Files != nil {
		if c.Files.Cert != "" {
			n.cert = c.Files.Cert
		}
		if c.Files.Key != "" {
			n.key = c.Files.Key
		}
		if c.Files.CA != "" {
			n.ca = c.Files.CA
		}
	}
	return filepath.Join(c.Destination, n.cert),
		filepath.Join(c.Destination, n.key),
		filepath.Join(c.Destination, n.ca)
}
