// Package auto picks the credential backend for the platform it is built for.
//
// It exists for multiplatform CLIs that just want "whatever this machine has".
// Code that knows its environment should skip it and inject the backend
// directly — a browser application imports keyring/browser, not this package.
package auto

import "github.com/tinywasm/keyring"

// Keyring is an alias so callers need only this import.
type Keyring = keyring.Keyring

// NewKeyring is keyring.NewKeyring with the platform's provider already chosen.
func NewKeyring(service string) (*Keyring, error) {
	return keyring.NewKeyring(service, Provider())
}

// OpenKeyring is keyring.OpenKeyring with the platform's provider already chosen.
func OpenKeyring(service string) *Keyring {
	return keyring.OpenKeyring(service, Provider())
}

// New is keyring.New with the platform's provider already chosen.
func New() *keyring.KeyManager { return keyring.New(Provider()) }
