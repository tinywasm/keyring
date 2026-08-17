//go:build !linux && !darwin && !windows && !wasm

package auto

import "github.com/tinywasm/keyring"

// Provider returns Fallback on unsupported platforms.
func Provider() keyring.Provider { return keyring.Fallback{} }
