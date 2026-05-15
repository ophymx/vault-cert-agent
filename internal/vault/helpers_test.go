package vault

import (
	"io"
	"log/slog"
	"testing"
)

// testLogger returns a logger that writes to t.Log so test output
// stays attached to the failing test.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
