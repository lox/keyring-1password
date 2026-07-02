package onepassword

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	opsdk "github.com/1password/onepassword-sdk-go"
	"github.com/lox/keyring/v2"
)

const (
	usernameFieldID   = "username"
	credentialFieldID = "credential"
	typeFieldID       = "type"
	filenameFieldID   = "filename"
	validFromFieldID  = "validFrom"
	expiresFieldID    = "expires"
	hostnameFieldID   = "hostname"
)

type itemsClient interface {
	List(context.Context, string, ...opsdk.ItemListFilter) ([]opsdk.ItemOverview, error)
	Get(context.Context, string, string) (opsdk.Item, error)
	Create(context.Context, opsdk.ItemCreateParams) (opsdk.Item, error)
	Put(context.Context, opsdk.Item) (opsdk.Item, error)
	Delete(context.Context, string, string) error
}

type retainedItemsClient struct {
	items  itemsClient
	client *opsdk.Client
}

func (c *retainedItemsClient) List(ctx context.Context, vaultID string, filters ...opsdk.ItemListFilter) ([]opsdk.ItemOverview, error) {
	defer runtime.KeepAlive(c.client)

	items, err := c.items.List(ctx, vaultID, filters...)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}

	return items, nil
}

func (c *retainedItemsClient) Get(ctx context.Context, vaultID string, itemID string) (opsdk.Item, error) {
	defer runtime.KeepAlive(c.client)

	item, err := c.items.Get(ctx, vaultID, itemID)
	if err != nil {
		return opsdk.Item{}, fmt.Errorf("get item: %w", err)
	}

	return item, nil
}

func (c *retainedItemsClient) Create(ctx context.Context, params opsdk.ItemCreateParams) (opsdk.Item, error) {
	defer runtime.KeepAlive(c.client)

	item, err := c.items.Create(ctx, params)
	if err != nil {
		return opsdk.Item{}, fmt.Errorf("create item: %w", err)
	}

	return item, nil
}

func (c *retainedItemsClient) Put(ctx context.Context, item opsdk.Item) (opsdk.Item, error) {
	defer runtime.KeepAlive(c.client)

	updated, err := c.items.Put(ctx, item)
	if err != nil {
		return opsdk.Item{}, fmt.Errorf("put item: %w", err)
	}

	return updated, nil
}

func (c *retainedItemsClient) Delete(ctx context.Context, vaultID string, itemID string) error {
	defer runtime.KeepAlive(c.client)

	if err := c.items.Delete(ctx, vaultID, itemID); err != nil {
		return fmt.Errorf("delete item: %w", err)
	}

	return nil
}

type onePasswordKeyring struct {
	items   itemsClient
	vaultID string
	title   string
	timeout time.Duration
}

func newKeyring(items itemsClient, cfg resolvedConfig) keyring.Keyring {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &onePasswordKeyring{
		items:   items,
		vaultID: cfg.Vault,
		title:   cfg.ItemTitle,
		timeout: timeout,
	}
}

func DesktopAuthSupported() bool {
	return desktopAuthSupported
}

func (k *onePasswordKeyring) Get(ctx context.Context, key string) (keyring.Item, error) {
	item, err := k.findItem(ctx, key)
	if err != nil {
		return keyring.Item{}, err
	}

	return keyringItemFromOnePassword(item)
}

func (k *onePasswordKeyring) Metadata(ctx context.Context, key string) (keyring.Metadata, error) {
	item, err := k.findItem(ctx, key)
	if err != nil {
		return keyring.Metadata{}, err
	}

	out, err := keyringItemFromOnePassword(item)
	if err != nil {
		return keyring.Metadata{}, err
	}
	out.Data = nil

	modified := item.UpdatedAt
	if modified.IsZero() {
		modified = item.CreatedAt
	}

	return keyring.Metadata{Item: &out, ModificationTime: modified}, nil
}

func (k *onePasswordKeyring) Set(ctx context.Context, item keyring.Item) error {
	if strings.TrimSpace(item.Key) == "" {
		return keyring.ErrNotFound
	}

	existing, err := k.findItem(ctx, item.Key)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}

	if errors.Is(err, keyring.ErrNotFound) {
		template, templateErr := k.findEmptyItem(ctx)
		if templateErr != nil && !errors.Is(templateErr, keyring.ErrNotFound) {
			return templateErr
		}

		if templateErr == nil {
			existing = template
			err = nil
		}
	}

	opCtx, cancel := k.context(ctx)
	defer cancel()

	if errors.Is(err, keyring.ErrNotFound) {
		_, err = k.items.Create(opCtx, opsdk.ItemCreateParams{
			Category: opsdk.ItemCategoryAPICredentials,
			VaultID:  k.vaultID,
			Title:    k.title,
			Fields:   itemFields(item),
			Tags:     []string{DefaultTag},
		})
		if err != nil {
			return fmt.Errorf("create 1Password keyring item: %w", err)
		}

		return nil
	}

	existing.Title = k.title
	existing.Category = opsdk.ItemCategoryAPICredentials
	existing.VaultID = k.vaultID
	existing.Fields = itemFields(item)
	existing.Tags = appendTag(existing.Tags)

	if _, err = k.items.Put(opCtx, existing); err != nil {
		return fmt.Errorf("update 1Password keyring item: %w", err)
	}

	return nil
}

func (k *onePasswordKeyring) Remove(ctx context.Context, key string) error {
	item, err := k.findItem(ctx, key)
	if err != nil {
		return err
	}

	opCtx, cancel := k.context(ctx)
	defer cancel()

	if err = k.items.Delete(opCtx, k.vaultID, item.ID); err != nil {
		if isNotFound(err) {
			return keyring.ErrNotFound
		}

		return fmt.Errorf("delete 1Password keyring item: %w", err)
	}

	return nil
}

func (k *onePasswordKeyring) Keys(ctx context.Context) ([]string, error) {
	overviews, err := k.listManagedItems(ctx)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(overviews))
	for _, overview := range overviews {
		item, getErr := k.getItem(ctx, overview.ID)
		if getErr != nil {
			if isNotFound(getErr) {
				continue
			}

			return nil, fmt.Errorf("read 1Password keyring item: %w", getErr)
		}

		key, ok := itemKeyField(item)
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys, nil
}

func (k *onePasswordKeyring) findItem(ctx context.Context, key string) (opsdk.Item, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return opsdk.Item{}, keyring.ErrNotFound
	}

	overviews, err := k.listManagedItems(ctx)
	if err != nil {
		return opsdk.Item{}, err
	}

	for _, overview := range overviews {
		item, err := k.getItemIfKeyMatches(ctx, overview.ID, key)
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return opsdk.Item{}, err
		}

		if err == nil {
			return item, nil
		}
	}

	return opsdk.Item{}, keyring.ErrNotFound
}

func (k *onePasswordKeyring) findEmptyItem(ctx context.Context) (opsdk.Item, error) {
	overviews, err := k.listActiveItems(ctx)
	if err != nil {
		return opsdk.Item{}, err
	}

	for _, overview := range overviews {
		if overview.Title != k.title {
			continue
		}

		item, err := k.getItem(ctx, overview.ID)
		if err != nil {
			if isNotFound(err) {
				continue
			}

			return opsdk.Item{}, fmt.Errorf("read 1Password keyring item: %w", err)
		}

		if !isReusableTemplateItem(item, k.title) {
			continue
		}

		return item, nil
	}

	return opsdk.Item{}, keyring.ErrNotFound
}

func (k *onePasswordKeyring) getItemIfKeyMatches(ctx context.Context, itemID string, key string) (opsdk.Item, error) {
	item, err := k.getItem(ctx, itemID)
	if err != nil {
		if isNotFound(err) {
			return opsdk.Item{}, keyring.ErrNotFound
		}

		return opsdk.Item{}, fmt.Errorf("read 1Password keyring item: %w", err)
	}

	storedKey, ok := itemKeyField(item)
	if !ok || storedKey != key {
		return opsdk.Item{}, keyring.ErrNotFound
	}

	return item, nil
}

func (k *onePasswordKeyring) getItem(ctx context.Context, itemID string) (opsdk.Item, error) {
	opCtx, cancel := k.context(ctx)
	defer cancel()

	item, err := k.items.Get(opCtx, k.vaultID, itemID)
	if err != nil {
		return opsdk.Item{}, fmt.Errorf("get 1Password keyring item: %w", err)
	}

	return item, nil
}

func (k *onePasswordKeyring) listManagedItems(ctx context.Context) ([]opsdk.ItemOverview, error) {
	overviews, err := k.listActiveItems(ctx)
	if err != nil {
		return nil, err
	}

	tagged := make([]opsdk.ItemOverview, 0, len(overviews))
	for _, overview := range overviews {
		if isKeyringItem(overview, k.title) {
			tagged = append(tagged, overview)
		}
	}

	return tagged, nil
}

func (k *onePasswordKeyring) listActiveItems(ctx context.Context) ([]opsdk.ItemOverview, error) {
	opCtx, cancel := k.context(ctx)
	defer cancel()

	overviews, err := k.items.List(opCtx, k.vaultID, opsdk.NewItemListFilterTypeVariantByState(&opsdk.ItemListFilterByStateInner{
		Active:   true,
		Archived: false,
	}))
	if err != nil {
		return nil, fmt.Errorf("list 1Password keyring items: %w", err)
	}

	return overviews, nil
}

func (k *onePasswordKeyring) context(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, k.timeout)
}

func itemFields(item keyring.Item) []opsdk.ItemField {
	value := base64.StdEncoding.EncodeToString(item.Data)

	return []opsdk.ItemField{
		{
			ID:        usernameFieldID,
			Title:     "username",
			Value:     item.Key,
			FieldType: opsdk.ItemFieldTypeText,
		},
		{
			ID:        credentialFieldID,
			Title:     "credential",
			Value:     value,
			FieldType: opsdk.ItemFieldTypeConcealed,
		},
		{
			ID:        typeFieldID,
			Title:     "type",
			Value:     item.Label,
			FieldType: opsdk.ItemFieldTypeMenu,
		},
		{
			ID:        filenameFieldID,
			Title:     "filename",
			FieldType: opsdk.ItemFieldTypeText,
		},
		{
			ID:        validFromFieldID,
			Title:     "valid from",
			FieldType: opsdk.ItemFieldTypeDate,
		},
		{
			ID:        expiresFieldID,
			Title:     "expires",
			FieldType: opsdk.ItemFieldTypeDate,
		},
		{
			ID:        hostnameFieldID,
			Title:     "hostname",
			Value:     item.Description,
			FieldType: opsdk.ItemFieldTypeText,
		},
	}
}

func keyringItemFromOnePassword(item opsdk.Item) (keyring.Item, error) {
	key, ok := itemKeyField(item)
	if !ok || strings.TrimSpace(key) == "" {
		return keyring.Item{}, keyring.ErrNotFound
	}

	encodedValue, ok := itemValueField(item)
	if !ok {
		return keyring.Item{}, fmt.Errorf("%w: item %q has no value field", ErrMissingValue, item.ID)
	}

	data, err := base64.StdEncoding.DecodeString(encodedValue)
	if err != nil {
		return keyring.Item{}, fmt.Errorf("decode 1Password keyring value: %w", err)
	}

	label, _ := itemLabelField(item)
	description, _ := itemDescriptionField(item)

	return keyring.Item{
		Key:         key,
		Data:        data,
		Label:       label,
		Description: description,
	}, nil
}

func itemKeyField(item opsdk.Item) (string, bool) {
	return itemField(item, usernameFieldID)
}

func itemValueField(item opsdk.Item) (string, bool) {
	return itemField(item, credentialFieldID)
}

func itemLabelField(item opsdk.Item) (string, bool) {
	return itemField(item, typeFieldID)
}

func itemDescriptionField(item opsdk.Item) (string, bool) {
	return itemField(item, hostnameFieldID)
}

func itemHasKeyringValue(item opsdk.Item) bool {
	key, keyOK := itemKeyField(item)
	value, valueOK := itemValueField(item)

	return (keyOK && strings.TrimSpace(key) != "") || (valueOK && strings.TrimSpace(value) != "")
}

func isReusableTemplateItem(item opsdk.Item, title string) bool {
	return item.Title == title &&
		item.Category == opsdk.ItemCategoryAPICredentials &&
		!itemHasKeyringValue(item)
}

func itemField(item opsdk.Item, id string) (string, bool) {
	for _, field := range item.Fields {
		if field.ID == id || field.Title == id {
			return field.Value, true
		}
	}

	return "", false
}

func appendTag(tags []string) []string {
	if hasTag(tags) {
		return tags
	}

	return append(tags, DefaultTag)
}

func hasTag(tags []string) bool {
	for _, tag := range tags {
		if tag == DefaultTag {
			return true
		}
	}

	return false
}

func isKeyringItem(overview opsdk.ItemOverview, title string) bool {
	return overview.Title == title &&
		overview.Category == opsdk.ItemCategoryAPICredentials &&
		hasTag(overview.Tags)
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, keyring.ErrNotFound) {
		return true
	}

	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "not found") || strings.Contains(msg, "notfound")
}
