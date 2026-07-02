//go:build !cgo && (darwin || linux)

package onepassword

import (
	"context"
	"errors"
	"testing"
)

func TestDesktopAuthRejectedWithoutCGO(t *testing.T) {
	if DesktopAuthSupported() {
		t.Fatal("desktop app auth unexpectedly supported")
	}

	_, err := newItemsClient(context.Background(), resolvedConfig{
		AuthMode: AuthDesktop,
		Account:  "example",
		Vault:    "vault",
		Timeout:  DefaultTimeout,
	})
	if !errors.Is(err, ErrDesktopAuthUnavailable) {
		t.Fatalf("error = %v, want %v", err, ErrDesktopAuthUnavailable)
	}
}
