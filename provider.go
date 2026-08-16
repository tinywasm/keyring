package keyring

import (
	"github.com/zalando/go-keyring"
)

// Provider abstracts the OS keyring backend (Secret Service, Keychain,
// Credential Manager). The default provider talks to the system; tests swap
// it with SetProvider to avoid touching real credentials.
type Provider interface {
	// Set stores password for user under service.
	Set(service, user, password string) error
	// Get returns the password stored for user under service.
	Get(service, user string) (string, error)
	// Delete removes the password stored for user under service.
	Delete(service, user string) error
	// DeleteAll removes every entry under service.
	DeleteAll(service string) error
}

type zalandoProvider struct{}

func (zalandoProvider) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}

func (zalandoProvider) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (zalandoProvider) Delete(service, user string) error {
	return keyring.Delete(service, user)
}

func (zalandoProvider) DeleteAll(service string) error {
	return keyring.DeleteAll(service)
}

var currentProvider Provider = zalandoProvider{}

// SetProvider replaces the OS keyring backend. Tests use it to inject an
// in-memory provider; production code never calls it.
func SetProvider(p Provider) {
	currentProvider = p
}

// GetProvider returns the active keyring backend. Used to restore the real
// provider after swapping it in tests.
func GetProvider() Provider {
	return currentProvider
}