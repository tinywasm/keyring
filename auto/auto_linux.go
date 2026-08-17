//go:build linux

package auto

import (
	"github.com/tinywasm/keyring"
	"github.com/tinywasm/keyring/linux"
)

// Provider returns the Secret Service backend.
func Provider() keyring.Provider { return linux.New() }
