//go:build windows

package auto

import (
	"github.com/tinywasm/keyring"
	"github.com/tinywasm/keyring/windows"
)

// Provider returns the Credential Manager backend.
func Provider() keyring.Provider { return windows.New() }
