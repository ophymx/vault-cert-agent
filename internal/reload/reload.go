// Package reload triggers service reloads after a cert is written.
//
// Two paths are supported and chosen per-cert from config:
//
//   - shell: cert.ReloadCommand → `/bin/sh -c <cmd>`. Same shape the
//     bash scripts used, kept for parity with arbitrary reload logic
//     (chained commands, reading auxiliary files, etc.).
//
//   - systemd via D-Bus: cert.ReloadUnits → a job on
//     org.freedesktop.systemd1.Manager via the system bus. Polkit
//     mediates the call, which means it is auditable and operators
//     can constrain it via rules. The /run/systemd/private socket —
//     which would bypass polkit because we run as root — is
//     deliberately NOT used.
//
// The D-Bus connection is opened lazily on first use and closed by
// Manager.Close().
package reload

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/ophymx/vault-cert-agent/internal/config"
)

// Manager dispatches a cert's configured reload. The zero value is
// not usable; construct via New.
type Manager struct {
	logger  *slog.Logger
	openBus func(ctx context.Context) (systemdBus, error)
	bus     systemdBus
}

// New returns a Manager that talks to systemd via the polkit-mediated
// system bus when a cert uses reload_units.
func New(logger *slog.Logger) *Manager {
	return &Manager{
		logger:  logger,
		openBus: defaultOpenBus,
	}
}

// Close releases the D-Bus connection if one was opened. Safe to call
// when nothing was opened.
func (m *Manager) Close() {
	if m.bus != nil {
		m.bus.Close()
		m.bus = nil
	}
}

// Reload triggers the configured reload (if any) for cert. Returns
// nil when no reload is configured — letting callers invoke it
// unconditionally.
func (m *Manager) Reload(ctx context.Context, cert config.CertConfig) error {
	switch {
	case len(cert.ReloadUnits) > 0:
		return m.reloadSystemd(ctx, cert)
	case cert.ReloadCommand != "":
		return m.reloadShell(ctx, cert)
	}
	return nil
}

func (m *Manager) reloadShell(ctx context.Context, cert config.CertConfig) error {
	log := m.logger.With("cert", cert.Name)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cert.ReloadCommand)
	out, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if len(out) > 0 {
		log.Info("reload output", "out", trimmed)
	}
	if err != nil {
		return fmt.Errorf("%w (output: %s)", err, trimmed)
	}
	return nil
}

func (m *Manager) reloadSystemd(ctx context.Context, cert config.CertConfig) error {
	method := cert.ReloadMethod
	if method == "" {
		method = config.DefaultReloadMethod
	}
	invoke, err := systemdMethod(method)
	if err != nil {
		return err
	}
	bus, err := m.connect(ctx)
	if err != nil {
		return fmt.Errorf("connect systemd: %w", err)
	}
	log := m.logger.With("cert", cert.Name, "method", method)
	for _, unit := range cert.ReloadUnits {
		if err := runSystemdJob(ctx, bus, invoke, unit, log); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) connect(ctx context.Context) (systemdBus, error) {
	if m.bus != nil {
		return m.bus, nil
	}
	b, err := m.openBus(ctx)
	if err != nil {
		return nil, err
	}
	m.bus = b
	return b, nil
}

// systemdInvoke abstracts the per-method *Conn call so dispatch is a
// table lookup. mode is always jobModeReplace.
type systemdInvoke func(ctx context.Context, bus systemdBus, name string, ch chan<- string) (int, error)

func systemdMethod(name string) (systemdInvoke, error) {
	switch name {
	case config.ReloadMethodReload:
		return func(ctx context.Context, b systemdBus, n string, ch chan<- string) (int, error) {
			return b.ReloadUnitContext(ctx, n, jobModeReplace, ch)
		}, nil
	case config.ReloadMethodRestart:
		return func(ctx context.Context, b systemdBus, n string, ch chan<- string) (int, error) {
			return b.RestartUnitContext(ctx, n, jobModeReplace, ch)
		}, nil
	case config.ReloadMethodTryRestart:
		return func(ctx context.Context, b systemdBus, n string, ch chan<- string) (int, error) {
			return b.TryRestartUnitContext(ctx, n, jobModeReplace, ch)
		}, nil
	case config.ReloadMethodReloadOrRestart:
		return func(ctx context.Context, b systemdBus, n string, ch chan<- string) (int, error) {
			return b.ReloadOrRestartUnitContext(ctx, n, jobModeReplace, ch)
		}, nil
	case config.ReloadMethodTryReloadOrRestart:
		return func(ctx context.Context, b systemdBus, n string, ch chan<- string) (int, error) {
			return b.ReloadOrTryRestartUnitContext(ctx, n, jobModeReplace, ch)
		}, nil
	}
	return nil, fmt.Errorf("unknown reload_method %q", name)
}

func runSystemdJob(ctx context.Context, bus systemdBus, invoke systemdInvoke, unit string, log *slog.Logger) error {
	ch := make(chan string, 1)
	if _, err := invoke(ctx, bus, unit, ch); err != nil {
		return fmt.Errorf("systemd %s: %w", unit, err)
	}
	select {
	case result := <-ch:
		log.Info("systemd job", "unit", unit, "result", result)
		// systemctl treats "done" and "skipped" as success; "skipped"
		// is what try-* operations report when the unit isn't running
		// or isn't loaded, which is exactly when we don't want to fail.
		if result != jobResultDone && result != jobResultSkipped {
			return fmt.Errorf("systemd %s: job result %s", unit, result)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

const (
	jobModeReplace = "replace"

	jobResultDone    = "done"
	jobResultSkipped = "skipped"
)
