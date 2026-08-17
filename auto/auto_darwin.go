//go:build darwin

package auto

import (
	"github.com/tinywasm/keyring"
	"github.com/tinywasm/keyring/darwin"
)

// Provider returns the Keychain backend.
func Provider() keyring.Provider { return darwin.New() }
