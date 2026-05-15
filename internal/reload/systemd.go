package reload

import (
	"context"

	systemddbus "github.com/coreos/go-systemd/v22/dbus"
)

// systemdBus is the subset of go-systemd's *dbus.Conn that the
// Manager touches. Tests substitute a fake implementation.
type systemdBus interface {
	Close()
	ReloadUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	RestartUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	TryRestartUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	ReloadOrRestartUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	ReloadOrTryRestartUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
}

// defaultOpenBus is the production factory: it opens an authenticated
// connection to the system bus, where every call is mediated by
// polkit (action org.freedesktop.systemd1.manage-units). This is
// deliberately NOT NewSystemdConnectionContext, which dials
// /run/systemd/private and bypasses polkit because we run as root.
func defaultOpenBus(ctx context.Context) (systemdBus, error) {
	return systemddbus.NewSystemConnectionContext(ctx)
}
