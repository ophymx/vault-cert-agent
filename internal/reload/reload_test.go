package reload

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ophymx/vault-cert-agent/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeBus records every method call and replies on the channel with
// the configured result string. Substituted in via Manager.openBus.
type fakeBus struct {
	mu       sync.Mutex
	calls    []call
	result   string
	respErr  error
	closeHit bool
}

type call struct {
	method string
	unit   string
	mode   string
}

func newFakeBus(result string) *fakeBus {
	return &fakeBus{result: result}
}

func (f *fakeBus) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeHit = true
}

func (f *fakeBus) record(method, unit, mode string, ch chan<- string) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call{method: method, unit: unit, mode: mode})
	result := f.result
	respErr := f.respErr
	f.mu.Unlock()
	if respErr != nil {
		return 0, respErr
	}
	ch <- result
	return 1, nil
}

func (f *fakeBus) ReloadUnitContext(_ context.Context, n, m string, ch chan<- string) (int, error) {
	return f.record("reload", n, m, ch)
}

func (f *fakeBus) RestartUnitContext(_ context.Context, n, m string, ch chan<- string) (int, error) {
	return f.record("restart", n, m, ch)
}

func (f *fakeBus) TryRestartUnitContext(_ context.Context, n, m string, ch chan<- string) (int, error) {
	return f.record("try-restart", n, m, ch)
}

func (f *fakeBus) ReloadOrRestartUnitContext(_ context.Context, n, m string, ch chan<- string) (int, error) {
	return f.record("reload-or-restart", n, m, ch)
}

func (f *fakeBus) ReloadOrTryRestartUnitContext(_ context.Context, n, m string, ch chan<- string) (int, error) {
	return f.record("try-reload-or-restart", n, m, ch)
}

func newManagerWithFake(bus *fakeBus) *Manager {
	m := New(discardLogger())
	m.openBus = func(context.Context) (systemdBus, error) { return bus, nil }
	return m
}

// ─── Shell path ──────────────────────────────────────────────────

func TestReload_NoActionIsNoOp(t *testing.T) {
	m := New(discardLogger())
	if err := m.Reload(context.Background(), config.CertConfig{Name: "c"}); err != nil {
		t.Errorf("no-action reload: got %v, want nil", err)
	}
}

func TestReload_ShellSuccess(t *testing.T) {
	m := New(discardLogger())
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "ran")
	cert := config.CertConfig{
		Name:          "c",
		ReloadCommand: "touch " + sentinel,
	}
	if err := m.Reload(context.Background(), cert); err != nil {
		t.Fatalf("shell reload: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("sentinel: %v", err)
	}
}

func TestReload_ShellNonZeroExitErrors(t *testing.T) {
	m := New(discardLogger())
	err := m.Reload(context.Background(), config.CertConfig{
		Name:          "c",
		ReloadCommand: "exit 9",
	})
	if err == nil {
		t.Fatal("expected error from exit 9")
	}
}

// ─── Systemd path ────────────────────────────────────────────────

func TestReload_SystemdDefaultMethodIsTryReloadOrRestart(t *testing.T) {
	bus := newFakeBus("done")
	m := newManagerWithFake(bus)
	cert := config.CertConfig{
		Name:        "c",
		ReloadUnits: []string{"pg_agentd.service"},
		// ReloadMethod left empty — should default.
	}
	if err := m.Reload(context.Background(), cert); err != nil {
		t.Fatalf("systemd reload: %v", err)
	}
	if len(bus.calls) != 1 {
		t.Fatalf("calls: got %d, want 1", len(bus.calls))
	}
	if bus.calls[0].method != "try-reload-or-restart" {
		t.Errorf("default method: got %q, want try-reload-or-restart", bus.calls[0].method)
	}
	if bus.calls[0].mode != "replace" {
		t.Errorf("mode: got %q, want replace", bus.calls[0].mode)
	}
}

func TestReload_SystemdMethodDispatch(t *testing.T) {
	cases := []struct {
		configured string
		want       string
	}{
		{config.ReloadMethodReload, "reload"},
		{config.ReloadMethodRestart, "restart"},
		{config.ReloadMethodTryRestart, "try-restart"},
		{config.ReloadMethodReloadOrRestart, "reload-or-restart"},
		{config.ReloadMethodTryReloadOrRestart, "try-reload-or-restart"},
	}
	for _, tc := range cases {
		t.Run(tc.configured, func(t *testing.T) {
			bus := newFakeBus("done")
			m := newManagerWithFake(bus)
			cert := config.CertConfig{
				Name:         "c",
				ReloadUnits:  []string{"u.service"},
				ReloadMethod: tc.configured,
			}
			if err := m.Reload(context.Background(), cert); err != nil {
				t.Fatal(err)
			}
			if bus.calls[0].method != tc.want {
				t.Errorf("method: got %q, want %q", bus.calls[0].method, tc.want)
			}
		})
	}
}

func TestReload_SystemdReloadsAllUnitsInOrder(t *testing.T) {
	bus := newFakeBus("done")
	m := newManagerWithFake(bus)
	cert := config.CertConfig{
		Name:        "c",
		ReloadUnits: []string{"a.service", "b.service", "c.service"},
	}
	if err := m.Reload(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if len(bus.calls) != 3 {
		t.Fatalf("calls: got %d, want 3", len(bus.calls))
	}
	for i, want := range []string{"a.service", "b.service", "c.service"} {
		if bus.calls[i].unit != want {
			t.Errorf("call %d unit: got %q, want %q", i, bus.calls[i].unit, want)
		}
	}
}

func TestReload_SystemdSkippedIsSuccess(t *testing.T) {
	// try-* methods return "skipped" when the unit isn't running.
	// That's normal operation, not failure.
	bus := newFakeBus("skipped")
	m := newManagerWithFake(bus)
	cert := config.CertConfig{
		Name:         "c",
		ReloadUnits:  []string{"u.service"},
		ReloadMethod: config.ReloadMethodTryReloadOrRestart,
	}
	if err := m.Reload(context.Background(), cert); err != nil {
		t.Errorf("skipped should be treated as success: %v", err)
	}
}

func TestReload_SystemdFailedResultErrors(t *testing.T) {
	bus := newFakeBus("failed")
	m := newManagerWithFake(bus)
	cert := config.CertConfig{
		Name:        "c",
		ReloadUnits: []string{"u.service"},
	}
	err := m.Reload(context.Background(), cert)
	if err == nil {
		t.Fatal("expected error from 'failed' job result")
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("error should mention failed result: %v", err)
	}
}

func TestReload_SystemdMethodCallError(t *testing.T) {
	bus := newFakeBus("done")
	bus.respErr = errors.New("permission denied")
	m := newManagerWithFake(bus)
	err := m.Reload(context.Background(), config.CertConfig{
		Name:        "c",
		ReloadUnits: []string{"u.service"},
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("expected wrapped bus error, got %v", err)
	}
}

func TestReload_BusOpenedLazilyAndOnce(t *testing.T) {
	var opens int
	bus := newFakeBus("done")
	m := New(discardLogger())
	m.openBus = func(context.Context) (systemdBus, error) {
		opens++
		return bus, nil
	}

	// Shell-only cert: no bus open.
	if err := m.Reload(context.Background(), config.CertConfig{Name: "a", ReloadCommand: "true"}); err != nil {
		t.Fatal(err)
	}
	if opens != 0 {
		t.Errorf("shell-only cert opened bus %d times, want 0", opens)
	}

	// Two systemd certs: bus opens once total.
	for _, name := range []string{"x", "y"} {
		if err := m.Reload(context.Background(), config.CertConfig{
			Name:        name,
			ReloadUnits: []string{"u.service"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if opens != 1 {
		t.Errorf("two systemd certs opened bus %d times, want 1", opens)
	}

	m.Close()
	if !bus.closeHit {
		t.Error("Close() did not close the underlying bus")
	}
}

