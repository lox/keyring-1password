package onepassword

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	opsdk "github.com/1password/onepassword-sdk-go"
	"github.com/lox/keyring/v2"
)

type fakeItems struct {
	items map[string]opsdk.Item
	next  int
}

func newFakeItems() *fakeItems {
	return &fakeItems{items: make(map[string]opsdk.Item)}
}

func TestItemsClientRetainsSDKClient(t *testing.T) {
	items, finalized := newFinalizableItemsClient()

	for range 3 {
		runtime.GC()
		runtime.Gosched()
	}

	select {
	case <-finalized:
		t.Fatal("SDK client finalized while its items client remained reachable")
	default:
	}

	if _, err := items.List(context.Background(), "vault"); err != nil {
		t.Fatalf("List: %v", err)
	}

	runtime.KeepAlive(items)
}

func newFinalizableItemsClient() (*retainedItemsClient, <-chan struct{}) {
	finalized := make(chan struct{}, 1)
	client := &opsdk.Client{}
	runtime.SetFinalizer(client, func(*opsdk.Client) {
		finalized <- struct{}{}
	})

	return &retainedItemsClient{
		items:  newFakeItems(),
		client: client,
	}, finalized
}

func (f *fakeItems) List(_ context.Context, vaultID string, _ ...opsdk.ItemListFilter) ([]opsdk.ItemOverview, error) {
	out := make([]opsdk.ItemOverview, 0, len(f.items))
	for _, item := range f.items {
		if item.VaultID != vaultID {
			continue
		}

		out = append(out, opsdk.ItemOverview{
			ID:        item.ID,
			Title:     item.Title,
			Category:  item.Category,
			VaultID:   item.VaultID,
			Tags:      item.Tags,
			CreatedAt: item.CreatedAt,
			UpdatedAt: item.UpdatedAt,
			State:     opsdk.ItemStateActive,
		})
	}

	return out, nil
}

func (f *fakeItems) Get(_ context.Context, vaultID string, itemID string) (opsdk.Item, error) {
	item, ok := f.items[itemID]
	if !ok || item.VaultID != vaultID {
		return opsdk.Item{}, keyring.ErrNotFound
	}

	return item, nil
}

func (f *fakeItems) Create(_ context.Context, params opsdk.ItemCreateParams) (opsdk.Item, error) {
	var id string

	for {
		f.next++
		id = fmt.Sprintf("item-%d", f.next)

		if _, exists := f.items[id]; !exists {
			break
		}
	}

	now := time.Unix(int64(f.next), 0).UTC()
	item := opsdk.Item{
		ID:        id,
		Title:     params.Title,
		Category:  params.Category,
		VaultID:   params.VaultID,
		Fields:    slices.Clone(params.Fields),
		Tags:      slices.Clone(params.Tags),
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	f.items[item.ID] = item

	return item, nil
}

func (f *fakeItems) Put(_ context.Context, item opsdk.Item) (opsdk.Item, error) {
	if _, ok := f.items[item.ID]; !ok {
		return opsdk.Item{}, keyring.ErrNotFound
	}

	item.Version++
	item.UpdatedAt = item.UpdatedAt.Add(time.Second)
	f.items[item.ID] = item

	return item, nil
}

func (f *fakeItems) Delete(_ context.Context, vaultID string, itemID string) error {
	item, ok := f.items[itemID]
	if !ok || item.VaultID != vaultID {
		return keyring.ErrNotFound
	}

	delete(f.items, itemID)

	return nil
}

func (f *fakeItems) onlyItem(t *testing.T) opsdk.Item {
	t.Helper()

	if len(f.items) != 1 {
		t.Fatalf("expected one item, got %d", len(f.items))
	}

	for _, item := range f.items {
		return item
	}

	t.Fatal("unreachable")

	return opsdk.Item{}
}

func TestKeyringRoundTrip(t *testing.T) {
	ctx := context.Background()
	fake := newFakeItems()
	ring := newKeyring(fake, resolvedConfig{
		Vault:     "vault",
		ItemTitle: "example-keyring",
		Timeout:   time.Second,
	})

	in := keyring.Item{
		Key:         "token:default:user@example.com",
		Data:        []byte{0, 1, 's', 'e', 'c', 'r', 'e', 't'},
		Label:       "token",
		Description: "refresh token",
	}

	if err := ring.Set(ctx, in); err != nil {
		t.Fatalf("Set: %v", err)
	}

	stored := fake.onlyItem(t)
	if strings.Contains(stored.Title, in.Key) {
		t.Fatalf("item title should not contain raw key: %q", stored.Title)
	}

	if stored.Title != "example-keyring" {
		t.Fatalf("unexpected item title: %q", stored.Title)
	}

	if stored.Category != opsdk.ItemCategoryAPICredentials {
		t.Fatalf("unexpected item category: %q", stored.Category)
	}

	if !hasTag(stored.Tags) {
		t.Fatalf("expected keyring tag, got %#v", stored.Tags)
	}

	if username, _ := itemField(stored, usernameFieldID); username != in.Key {
		t.Fatalf("unexpected username field: %q", username)
	}

	if credential, _ := itemField(stored, credentialFieldID); credential != base64.StdEncoding.EncodeToString(in.Data) {
		t.Fatalf("unexpected credential field: %q", credential)
	}

	got, err := ring.Get(ctx, in.Key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Key != in.Key || got.Label != in.Label || got.Description != in.Description || !slices.Equal(got.Data, in.Data) {
		t.Fatalf("unexpected item: %#v", got)
	}

	metadata, err := ring.(keyring.MetadataReader).Metadata(ctx, in.Key)
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}

	if metadata.Item == nil || metadata.Key != in.Key || len(metadata.Data) != 0 {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}

	keys, err := ring.Keys(ctx)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}

	if !slices.Equal(keys, []string{in.Key}) {
		t.Fatalf("unexpected keys: %#v", keys)
	}

	if err = ring.Remove(ctx, in.Key); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err = ring.Get(ctx, in.Key); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("expected key not found after remove, got %v", err)
	}
}

func TestKeyringSetUpdatesExistingItem(t *testing.T) {
	ctx := context.Background()
	fake := newFakeItems()
	ring := newKeyring(fake, resolvedConfig{
		Vault:     "vault",
		ItemTitle: "example-keyring",
		Timeout:   time.Second,
	})

	key := "default_account:default"
	if err := ring.Set(ctx, keyring.Item{Key: key, Data: []byte("old")}); err != nil {
		t.Fatalf("Set old: %v", err)
	}

	if err := ring.Set(ctx, keyring.Item{Key: key, Data: []byte("new")}); err != nil {
		t.Fatalf("Set new: %v", err)
	}

	if len(fake.items) != 1 {
		t.Fatalf("expected update in place, got %d items", len(fake.items))
	}

	got, err := ring.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if string(got.Data) != "new" {
		t.Fatalf("expected updated value, got %q", string(got.Data))
	}
}

func TestKeyringIgnoresUntaggedItem(t *testing.T) {
	ctx := context.Background()
	fake := newFakeItems()
	key := "token:default:user@example.com"
	fake.items["item-1"] = opsdk.Item{
		ID:       "item-1",
		Title:    "example-keyring",
		Category: opsdk.ItemCategoryAPICredentials,
		VaultID:  "vault",
		Fields: []opsdk.ItemField{
			{ID: usernameFieldID, Title: "username", Value: key, FieldType: opsdk.ItemFieldTypeText},
			{ID: credentialFieldID, Title: "credential", Value: base64.StdEncoding.EncodeToString([]byte("secret")), FieldType: opsdk.ItemFieldTypeConcealed},
		},
	}
	ring := newKeyring(fake, resolvedConfig{
		Vault:     "vault",
		ItemTitle: "example-keyring",
		Timeout:   time.Second,
	})

	_, err := ring.Get(ctx, key)
	if !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("expected untagged item to be ignored, got %v", err)
	}

	if err = ring.Set(ctx, keyring.Item{Key: key, Data: []byte("updated")}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if len(fake.items) != 2 {
		t.Fatalf("expected new managed item, got %d items", len(fake.items))
	}
}

func TestKeyringReusesEmptyTemplateItem(t *testing.T) {
	ctx := context.Background()
	fake := newFakeItems()
	fake.items["item-1"] = opsdk.Item{
		ID:       "item-1",
		Title:    "example-keyring",
		Category: opsdk.ItemCategoryAPICredentials,
		VaultID:  "vault",
		Fields: []opsdk.ItemField{
			{ID: usernameFieldID, Title: "username", FieldType: opsdk.ItemFieldTypeText},
			{ID: credentialFieldID, Title: "credential", FieldType: opsdk.ItemFieldTypeConcealed},
		},
	}
	ring := newKeyring(fake, resolvedConfig{
		Vault:     "vault",
		ItemTitle: "example-keyring",
		Timeout:   time.Second,
	})

	key := "token:default:user@example.com"
	if err := ring.Set(ctx, keyring.Item{Key: key, Data: []byte("secret")}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if len(fake.items) != 1 {
		t.Fatalf("expected template item to be reused, got %d items", len(fake.items))
	}

	updated := fake.items["item-1"]
	if username, _ := itemField(updated, usernameFieldID); username != key {
		t.Fatalf("unexpected username field: %q", username)
	}

	if !hasTag(updated.Tags) {
		t.Fatalf("expected reused item to be tagged, got %#v", updated.Tags)
	}
}

func TestProviderResolvesServiceAccountEnv(t *testing.T) {
	t.Setenv(ServiceAccountTokenEnv, "token")
	t.Setenv(VaultEnv, "")

	origNewClient := newItemsClient
	t.Cleanup(func() { newItemsClient = origNewClient })

	fake := newFakeItems()
	newItemsClient = func(_ context.Context, cfg resolvedConfig) (itemsClient, error) {
		if cfg.AuthMode != AuthServiceAccount || cfg.ServiceAccountToken != "token" || cfg.Vault != "vault" {
			t.Fatalf("unexpected config: %#v", cfg)
		}
		if cfg.ItemTitle != "example-keyring" {
			t.Fatalf("unexpected item title: %q", cfg.ItemTitle)
		}
		return fake, nil
	}

	ring, err := Provider(Vault("vault")).Open(context.Background(), keyring.OpenOptions{ServiceName: "example"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, ok := ring.(*onePasswordKeyring); !ok {
		t.Fatalf("expected onePasswordKeyring, got %T", ring)
	}
}

func TestResolveConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		envToken    string
		wantAuth    AuthMode
		wantAccount string
		wantErr     error
	}{
		{name: "service account", config: Config{Vault: "vault", ServiceAccountToken: "token"}, wantAuth: AuthServiceAccount},
		{name: "desktop", config: Config{Vault: "vault", Account: "account"}, wantAuth: AuthDesktop, wantAccount: "account"},
		{name: "env token", config: Config{Vault: "vault"}, envToken: "token", wantAuth: AuthServiceAccount},
		{name: "invalid auth", config: Config{Vault: "vault", AuthMode: "bad"}, wantErr: ErrInvalidAuthMode},
		{name: "missing vault", config: Config{ServiceAccountToken: "token"}, wantErr: ErrMissingVault},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(ServiceAccountTokenEnv, tt.envToken)

			got, err := resolveConfig(tt.config, "example")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveConfig: %v", err)
			}
			if got.AuthMode != tt.wantAuth || got.Account != tt.wantAccount {
				t.Fatalf("unexpected config: %#v", got)
			}
		})
	}
}

func TestNormalizeAuthModeAliases(t *testing.T) {
	tests := map[AuthMode]AuthMode{
		"":                AuthAuto,
		"auto":            AuthAuto,
		"service_account": AuthServiceAccount,
		"serviceaccount":  AuthServiceAccount,
		"sa":              AuthServiceAccount,
		"local":           AuthDesktop,
		"desktop-app":     AuthDesktop,
		"desktop_app":     AuthDesktop,
	}

	for raw, want := range tests {
		if got := normalizeAuthMode(raw); got != want {
			t.Fatalf("normalizeAuthMode(%q) = %q, want %q", raw, got, want)
		}
	}
}
