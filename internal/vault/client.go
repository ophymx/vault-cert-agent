// Package vault wraps github.com/hashicorp/vault/api with the small
// shape vault-cert-agent needs: AppRole login at startup, then a few
// Read/Write calls on per-source paths. Keeping the wrapper lets the
// rest of the agent depend on a tiny stable surface instead of all of
// vault/api.
package vault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/ophymx/vault-cert-agent/internal/config"
)

const defaultTimeout = 30 * time.Second

// Client speaks to a Vault server with a single AppRole-issued token
// for the lifetime of one process invocation.
type Client struct {
	api    *vaultapi.Client
	logger *slog.Logger
}

// Response is an alias for *api.Secret. Sources only touch .Data, but
// exposing the underlying type avoids a translation layer.
type Response = vaultapi.Secret

// NewClient reads the AppRole credentials from disk, performs the
// login, and returns a Client carrying the issued token. It does not
// renew the token — vault-cert-agent is one-shot.
func NewClient(ctx context.Context, cfg config.VaultConfig, logger *slog.Logger) (*Client, error) {
	roleID, err := readSecret(cfg.RoleIDFile)
	if err != nil {
		return nil, fmt.Errorf("read role_id: %w", err)
	}
	secretID, err := readSecret(cfg.SecretIDFile)
	if err != nil {
		return nil, fmt.Errorf("read secret_id: %w", err)
	}

	apiCfg := vaultapi.DefaultConfig()
	apiCfg.Address = strings.TrimRight(cfg.URL, "/")
	apiCfg.Timeout = defaultTimeout
	// 1 retry == 2 total attempts, matching the original hand-rolled
	// behaviour. vault/api retries on connection errors and 5xx; it
	// does not retry 4xx, which is what we want.
	apiCfg.MaxRetries = 1
	if apiCfg.Error != nil {
		return nil, fmt.Errorf("vault config: %w", apiCfg.Error)
	}

	apiClient, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}

	c := &Client{api: apiClient, logger: logger}
	if err := c.login(ctx, cfg.LoginPath, roleID, secretID); err != nil {
		return nil, fmt.Errorf("vault login: %w", err)
	}
	return c, nil
}

// Read does a GET on /v1/<path> with optional query params.
func (c *Client) Read(ctx context.Context, path string, params url.Values) (*Response, error) {
	resp, err := c.api.Logical().ReadWithDataWithContext(ctx, path, params)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("vault read %s: empty response", path)
	}
	return resp, nil
}

// Write does a POST on /v1/<path> with a JSON-encoded body.
func (c *Client) Write(ctx context.Context, path string, payload map[string]any) (*Response, error) {
	resp, err := c.api.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("vault write %s: empty response", path)
	}
	return resp, nil
}

func (c *Client) login(ctx context.Context, loginPath, roleID, secretID string) error {
	resp, err := c.api.Logical().WriteWithContext(ctx, loginPath, map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return err
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return errors.New("login response had empty client_token")
	}
	c.api.SetToken(resp.Auth.ClientToken)
	c.logger.Debug("vault login ok", "login_path", loginPath)
	return nil
}

// readSecret loads an AppRole credential file (role_id or secret_id).
// Refuses to read if any group/other bits are set or if path is a
// symlink — both would mean the AppRole identity is leaking outside
// the agent's trust boundary, and silently accepting that turns a
// misconfig into a credential disclosure.
func readSecret(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file (mode %s)", path, info.Mode())
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s has mode %o; expected no group/other access (use 0600)", path, perm)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s: file is empty", path)
	}
	return s, nil
}
