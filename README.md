keyring-1password
=================
[![CI](https://github.com/lox/keyring-1password/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/lox/keyring-1password/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lox/keyring-1password.svg)](https://pkg.go.dev/github.com/lox/keyring-1password)

1Password provider for [`github.com/lox/keyring/v2`](https://github.com/lox/keyring).

This module uses [`github.com/lox/onepassword-sdk-native-go`](https://github.com/lox/onepassword-sdk-native-go)
to keep 1Password support outside the core keyring module without pulling in
the official SDK's WASM/runtime stack.

## Usage

```bash
go get github.com/lox/keyring-1password
```

```go
import (
	"context"

	"github.com/lox/keyring/v2"
	onepassword "github.com/lox/keyring-1password"
)

ctx := context.Background()

ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithProvider(onepassword.Provider(
		onepassword.Vault("vault-id"),
	)),
)
```

By default, `Provider` uses service-account auth and reads the token from
`OP_SERVICE_ACCOUNT_TOKEN`. You can pass the token directly instead:

```go
onepassword.Provider(
	onepassword.Vault("vault-id"),
	onepassword.ServiceAccountToken(token),
)
```

Desktop app auth is opt-in and requires a compatible CGO-enabled build:

```go
onepassword.Provider(
	onepassword.Auth(onepassword.AuthDesktop),
	onepassword.Account("my.1password.com"),
	onepassword.Vault("vault-id"),
)
```

`Provider` accepts `Auth`, `ServiceAccountToken`, `Account`, `Vault`,
`ItemTitle`, `Timeout`, and `Integration` options. On missing auth or vault
configuration, it returns `keyring.ErrUnavailable` during open so callers can
fall back to another provider.
