//go:build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/goreleaser/nfpm/v2"
	_ "github.com/goreleaser/nfpm/v2/deb"
	"github.com/magefile/mage/sh"
)

// Build compiles vault-cert-agent for Linux. Target arch is read from
// GOARCH (default: amd64).
func Build() error {
	return buildBinary(targetArch())
}

// Package builds the binary and produces a .deb under dist/pkg/.
// Target arch is read from GOARCH (default: amd64).
func Package() error {
	arch := targetArch()
	if err := buildBinary(arch); err != nil {
		return err
	}
	return packageDeb(arch)
}

// Clean removes the dist/ directory.
func Clean() error {
	fmt.Println("Cleaning dist/...")
	return os.RemoveAll("dist")
}

func buildBinary(arch string) error {
	binDir := filepath.Join("dist", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	version := resolveVersion()
	out := filepath.Join(binDir, "vault-cert-agent")
	env := map[string]string{"GOOS": "linux", "GOARCH": arch}
	fmt.Printf("==> Building vault-cert-agent (linux/%s, version=%s)\n", arch, version)
	return sh.RunWith(env, "go", "build",
		"-trimpath",
		"-ldflags=-s -w -X main.version="+version,
		"-o", out,
		"./cmd/vault-cert-agent",
	)
}

func packageDeb(arch string) error {
	info := nfpmInfo(nfpmArch(arch), resolveVersion())
	if err := nfpm.Validate(info); err != nil {
		return fmt.Errorf("validate nfpm config: %w", err)
	}

	packager, err := nfpm.Get("deb")
	if err != nil {
		return err
	}

	pkgDir := filepath.Join("dist", "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return err
	}

	target := filepath.Join(pkgDir, packager.ConventionalFileName(info))
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Printf("==> Packaging deb: %s\n", target)
	if err := packager.Package(info, f); err != nil {
		_ = os.Remove(target)
		return fmt.Errorf("nfpm package: %w", err)
	}
	fmt.Printf("==> Done: %s\n", target)
	return nil
}

func nfpmArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return goarch
	}
}

func targetArch() string {
	if a := os.Getenv("GOARCH"); a != "" {
		return a
	}
	return "amd64"
}

// resolveVersion returns a string suitable for both the binary's
// -X main.version ldflag and the Debian package Version field. Falls
// back to a deterministic dev tag when git metadata isn't available
// (e.g. building from a tarball or an un-init'd worktree).
func resolveVersion() string {
	out, err := exec.Command("git", "describe", "--tags", "--dirty", "--always").Output()
	if err != nil {
		return "0.0.0-dev"
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
}
