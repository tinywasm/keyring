//go:build wasm

package auto

import (
	"github.com/tinywasm/keyring"
	"github.com/tinywasm/keyring/browser"
)

// Provider returns the WebCrypto/IndexedDB backend.
func Provider() keyring.Provider { return browser.New() }
