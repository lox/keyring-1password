package onepassword

import "github.com/lox/keyring/v2"

type Item = keyring.Item
type Metadata = keyring.Metadata

const OnePasswordBackend = Backend

var (
	ErrKeyNotFound = keyring.ErrKeyNotFound
	ErrUnavailable = keyring.ErrUnavailable
)
