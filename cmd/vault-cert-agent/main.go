// Command vault-cert-agent fetches TLS material from Vault and writes
// it to disk for local consumers. One-shot binary; driven by a
// systemd timer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/ophymx/vault-cert-agent/internal/config"
	"github.com/ophymx/vault-cert-agent/internal/reload"
	"github.com/ophymx/vault-cert-agent/internal/renewer"
	"github.com/ophymx/vault-cert-agent/internal/source"
	"github.com/ophymx/vault-cert-agent/internal/vault"
	"github.com/ophymx/vault-cert-agent/internal/writer"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

const (
	exitOK      = 0
	exitStartup = 1
	exitPartial = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("vault-cert-agent", flag.ContinueOnError)
	var (
		configPath = fs.String("config", "/etc/vault-cert-agent/config.hcl", "path to config")
		dryRun     = fs.Bool("dry-run", false, "report what would happen, don't fetch or write")
		force      = fs.Bool("force", false, "ignore TTL threshold, refetch every cert")
		verbose    = fs.Bool("verbose", false, "log per-cert decision rationale (sets level=debug)")
		logFormat  = fs.String("log-format", "text", `"text" (default) or "json"`)
		showVer    = fs.Bool("version", false, "print version and exit")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitStartup
	}
	if *showVer {
		fmt.Println(versionString())
		return exitOK
	}

	logger, err := newLogger(*logFormat, *verbose)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitStartup
	}
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config", "path", *configPath, "err", err)
		return exitStartup
	}
	logger.Info("config loaded", "path", *configPath, "certs", len(cfg.Certs))
	logger.Debug("flags", "dry_run", *dryRun, "force", *force)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	vc, err := vault.NewClient(ctx, cfg.Vault, logger)
	if err != nil {
		logger.Error("vault auth", "err", err)
		return exitStartup
	}

	reloadMgr := reload.New(logger)
	defer reloadMgr.Close()

	r := renewer.New(
		source.NewRegistry(vc),
		writer.New(logger),
		reloadMgr,
		logger,
		renewer.Options{
			ThresholdFraction: cfg.Renewal.ThresholdFraction,
			Force:             *force,
			DryRun:            *dryRun,
		},
	)

	failures := r.Run(ctx, cfg.Certs)
	if failures > 0 {
		logger.Error("run finished with failures", "failed", failures, "total", len(cfg.Certs))
		return exitPartial
	}
	logger.Info("run finished", "certs", len(cfg.Certs))
	return exitOK
}

func newLogger(format string, verbose bool) (*slog.Logger, error) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch format {
	case "text":
		h = slog.NewTextHandler(os.Stderr, opts)
	case "json":
		h = slog.NewJSONHandler(os.Stderr, opts)
	default:
		return nil, fmt.Errorf("unknown log format %q (want text or json)", format)
	}
	return slog.New(h), nil
}

func versionString() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
