//go:build wasm

package browser

import (
	"syscall/js"

	"github.com/tinywasm/keyring"
)

var (
	jsCrypto        = js.Global().Get("crypto")
	jsUint8Array    = js.Global().Get("Uint8Array")
	jsObject        = js.Global().Get("Object")
	cachedDEKHandle js.Value
)

func getSubtle() js.Value {
	if !jsCrypto.Truthy() {
		return js.Undefined()
	}
	return jsCrypto.Get("subtle")
}

func checkAvailable() error {
	subtle := getSubtle()
	if !subtle.Truthy() || !js.Global().Get("indexedDB").Truthy() {
		return keyring.ErrUnavailable
	}
	return nil
}

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (p *Provider) Set(service, key, value string) error {
	if err := checkAvailable(); err != nil {
		return err
	}
	dek, err := ensureKeys()
	if err != nil {
		return keyring.Wrap("keyring/browser: ensureKeys", err)
	}

	ivBytes := make([]byte, 12)
	jsCrypto.Call("getRandomValues", sliceToUint8Array(ivBytes))

	ciphertext, err := encryptAESGCM(dek, ivBytes, []byte(value))
	if err != nil {
		return keyring.Wrap("keyring/browser: encrypt", err)
	}

	recordID := secretID(service, key)
	if err := putSecretRecord(recordID, ivBytes, ciphertext); err != nil {
		return keyring.Wrap("keyring/browser: putSecretRecord", err)
	}
	return nil
}

func (p *Provider) Get(service, key string) (string, error) {
	if err := checkAvailable(); err != nil {
		return "", err
	}
	dek, err := ensureKeys()
	if err != nil {
		return "", keyring.Wrap("keyring/browser: ensureKeys", err)
	}

	recordID := secretID(service, key)
	rec, err := getSecretRecord(recordID)
	if err != nil {
		return "", err
	}

	plaintext, err := decryptAESGCM(dek, rec.iv, rec.data)
	if err != nil {
		return "", keyring.Wrap("keyring/browser: decrypt", err)
	}
	return string(plaintext), nil
}

func (p *Provider) Delete(service, key string) error {
	if err := checkAvailable(); err != nil {
		return err
	}
	recordID := secretID(service, key)
	return deleteSecretRecord(recordID)
}

func (p *Provider) DeleteAll(service string) error {
	if service == "" {
		return keyring.ErrNotFound
	}
	if err := checkAvailable(); err != nil {
		return err
	}
	return deleteServiceSecrets(service)
}

func secretID(service, key string) string {
	return service + "\x00" + key
}

func sliceToUint8Array(b []byte) js.Value {
	arr := jsUint8Array.New(len(b))
	js.CopyBytesToJS(arr, b)
	return arr
}

func uint8ArrayToSlice(arr js.Value) []byte {
	b := make([]byte, arr.Get("length").Int())
	js.CopyBytesToGo(b, arr)
	return b
}

func arrayBufferToSlice(ab js.Value) []byte {
	return uint8ArrayToSlice(jsUint8Array.New(ab))
}
