// Package onepassword provides a 1Password provider for github.com/lox/keyring/v2.
package onepassword

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	opsdk "github.com/1password/onepassword-sdk-go"
	"github.com/lox/keyring/v2"
)

const (
	Backend keyring.Backend = "1password"

	ServiceAccountTokenEnv = "OP_SERVICE_ACCOUNT_TOKEN" //nolint:gosec // env var name, not a credential value
	VaultEnv               = "KEYRING_1PASSWORD_VAULT"
)

const (
	DefaultTimeout            = 10 * time.Second
	DefaultItemTitle          = "keyring"
	DefaultTag                = "keyring-1password"
	DefaultIntegrationName    = "keyring-1password"
	DefaultIntegrationVersion = "provider"
)

type AuthMode string

const (
	AuthAuto           AuthMode = "auto"
	AuthDesktop        AuthMode = "desktop"
	AuthServiceAccount AuthMode = "service-account"
)

var (
	ErrMissingToken           = errors.New("missing 1Password service account token")
	ErrMissingAccount         = errors.New("missing 1Password account")
	ErrMissingVault           = errors.New("missing 1Password vault")
	ErrInvalidAuthMode        = errors.New("invalid 1Password auth mode")
	ErrDesktopAuthUnavailable = errors.New("1Password desktop app auth is unavailable in this build")
	ErrMissingValue           = errors.New("missing 1Password keyring value")
)

type Option func(*Config)

type Config struct {
	AuthMode            AuthMode
	ServiceAccountToken string
	Account             string
	Vault               string
	ItemTitle           string
	Timeout             time.Duration
	IntegrationName     string
	IntegrationVersion  string
}

func Auth(mode AuthMode) Option {
	return func(cfg *Config) { cfg.AuthMode = mode }
}

func ServiceAccountToken(token string) Option {
	return func(cfg *Config) { cfg.ServiceAccountToken = token }
}

func Account(account string) Option {
	return func(cfg *Config) { cfg.Account = account }
}

func Vault(vault string) Option {
	return func(cfg *Config) { cfg.Vault = vault }
}

func ItemTitle(title string) Option {
	return func(cfg *Config) { cfg.ItemTitle = title }
}

func Timeout(timeout time.Duration) Option {
	return func(cfg *Config) { cfg.Timeout = timeout }
}

func Integration(name string, version string) Option {
	return func(cfg *Config) {
		cfg.IntegrationName = name
		cfg.IntegrationVersion = version
	}
}

func Provider(opts ...Option) keyring.Provider {
	cfg := Config{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return keyring.Provider{
		Backend: Backend,
		Open: func(ctx context.Context, open keyring.OpenOptions) (keyring.Keyring, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			resolved, err := resolveConfig(cfg, open.ServiceName)
			if err != nil {
				return nil, err
			}

			clientCtx, cancel := context.WithTimeout(ctx, resolved.Timeout)
			defer cancel()

			items, err := newItemsClient(clientCtx, resolved)
			if err != nil {
				return nil, fmt.Errorf("open 1Password keyring: %w", err)
			}

			return newKeyring(items, resolved), nil
		},
	}
}

type resolvedConfig struct {
	AuthMode            AuthMode
	ServiceAccountToken string
	Account             string
	Vault               string
	ItemTitle           string
	Timeout             time.Duration
	IntegrationName     string
	IntegrationVersion  string
}

func resolveConfig(cfg Config, serviceName string) (resolvedConfig, error) {
	timeout := cfg.Timeout
	if timeout < 0 {
		return resolvedConfig{}, fmt.Errorf("%w: timeout must be positive", keyring.ErrInvalidOption)
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	authMode := normalizeAuthMode(cfg.AuthMode)
	account := strings.TrimSpace(cfg.Account)
	token := strings.TrimSpace(cfg.ServiceAccountToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv(ServiceAccountTokenEnv))
	}

	if authMode == "" || authMode == AuthAuto {
		if account != "" {
			authMode = AuthDesktop
		} else {
			authMode = AuthServiceAccount
		}
	}

	switch authMode {
	case AuthAuto:
		return resolvedConfig{}, fmt.Errorf("%w: %w: %q", keyring.ErrInvalidOption, ErrInvalidAuthMode, cfg.AuthMode)
	case AuthDesktop:
		if account == "" {
			return resolvedConfig{}, fmt.Errorf("%w: %w", keyring.ErrUnavailable, ErrMissingAccount)
		}
	case AuthServiceAccount:
		if token == "" {
			return resolvedConfig{}, fmt.Errorf("%w: %w", keyring.ErrUnavailable, ErrMissingToken)
		}
	default:
		return resolvedConfig{}, fmt.Errorf("%w: %w: %q", keyring.ErrInvalidOption, ErrInvalidAuthMode, cfg.AuthMode)
	}

	vault := strings.TrimSpace(cfg.Vault)
	if vault == "" {
		vault = strings.TrimSpace(os.Getenv(VaultEnv))
	}
	if vault == "" {
		return resolvedConfig{}, fmt.Errorf("%w: %w", keyring.ErrUnavailable, ErrMissingVault)
	}

	itemTitle := strings.TrimSpace(cfg.ItemTitle)
	if itemTitle == "" {
		itemTitle = defaultItemTitle(serviceName)
	}

	integrationName := strings.TrimSpace(cfg.IntegrationName)
	if integrationName == "" {
		integrationName = DefaultIntegrationName
	}

	integrationVersion := strings.TrimSpace(cfg.IntegrationVersion)
	if integrationVersion == "" {
		integrationVersion = DefaultIntegrationVersion
	}

	return resolvedConfig{
		AuthMode:            authMode,
		ServiceAccountToken: token,
		Account:             account,
		Vault:               vault,
		ItemTitle:           itemTitle,
		Timeout:             timeout,
		IntegrationName:     integrationName,
		IntegrationVersion:  integrationVersion,
	}, nil
}

func normalizeAuthMode(raw AuthMode) AuthMode {
	switch strings.ToLower(strings.TrimSpace(string(raw))) {
	case "", "auto":
		return AuthAuto
	case "service_account", "serviceaccount", "sa":
		return AuthServiceAccount
	case "app", "local", "desktop-app", "desktop_app":
		return AuthDesktop
	default:
		return AuthMode(strings.ToLower(strings.TrimSpace(string(raw))))
	}
}

func defaultItemTitle(serviceName string) string {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return DefaultItemTitle
	}

	return serviceName + "-keyring"
}

var newItemsClient = func(ctx context.Context, cfg resolvedConfig) (itemsClient, error) {
	opts := []opsdk.ClientOption{
		opsdk.WithIntegrationInfo(cfg.IntegrationName, cfg.IntegrationVersion),
	}

	switch cfg.AuthMode {
	case AuthAuto:
		return nil, fmt.Errorf("%w: %w: %q", keyring.ErrInvalidOption, ErrInvalidAuthMode, cfg.AuthMode)
	case AuthDesktop:
		if !DesktopAuthSupported() {
			return nil, fmt.Errorf("%w: %w", keyring.ErrUnavailable, ErrDesktopAuthUnavailable)
		}
		opts = append(opts, opsdk.WithDesktopAppIntegration(cfg.Account))
	case AuthServiceAccount:
		opts = append(opts, opsdk.WithServiceAccountToken(cfg.ServiceAccountToken))
	default:
		return nil, fmt.Errorf("%w: %w: %q", keyring.ErrInvalidOption, ErrInvalidAuthMode, cfg.AuthMode)
	}

	client, err := opsdk.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("new 1Password client: %w", err)
	}

	return &retainedItemsClient{
		items:  client.Items(),
		client: client,
	}, nil
}
