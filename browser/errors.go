//go:build wasm

package browser

import "github.com/tinywasm/keyring"

const (
	ErrPasskeyUnsupported keyring.Error = "keyring: authenticator does not support the prf extension"
	ErrPasskeyNotEnrolled  keyring.Error = "keyring: no passkey enrolled for this keyring"
)
