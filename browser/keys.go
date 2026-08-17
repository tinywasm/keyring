//go:build wasm

package browser

import (
	"syscall/js"

	_ "github.com/tinywasm/await"
	"github.com/tinywasm/keyring"
)

func ensureKeys() (js.Value, error) {
	if cachedDEKHandle.Truthy() {
		return cachedDEKHandle, nil
	}

	kekRec, err := getKEKRecord("device")
	if err == nil && kekRec.Key.Truthy() && len(kekRec.WrappedDEK) > 0 {
		dek, err := unwrapDEK(kekRec.WrappedDEK, kekRec.Key, false)
		if err == nil {
			cachedDEKHandle = dek
			return dek, nil
		}
	}

	subtle := getSubtle()

	genKEKOpts := jsObject.New()
	genKEKOpts.Set("name", "AES-KW")
	genKEKOpts.Set("length", 256)
	usagesKEK := js.Global().Get("Array").New("wrapKey", "unwrapKey")

	kekPromise := subtle.Call("generateKey", genKEKOpts, false, usagesKEK)
	deviceKEK, err := awaitPromise(kekPromise)
	if err != nil {
		return js.Undefined(), keyring.Wrap("keyring/browser: generate device KEK", err)
	}

	genDEKOpts := jsObject.New()
	genDEKOpts.Set("name", "AES-GCM")
	genDEKOpts.Set("length", 256)
	usagesDEK := js.Global().Get("Array").New("encrypt", "decrypt")

	dekPromise := subtle.Call("generateKey", genDEKOpts, true, usagesDEK)
	tempDEK, err := awaitPromise(dekPromise)
	if err != nil {
		return js.Undefined(), keyring.Wrap("keyring/browser: generate DEK", err)
	}

	wrapPromise := subtle.Call("wrapKey", "raw", tempDEK, deviceKEK, "AES-KW")
	wrappedAB, err := awaitPromise(wrapPromise)
	if err != nil {
		return js.Undefined(), keyring.Wrap("keyring/browser: wrap DEK", err)
	}

	wrappedDEK := arrayBufferToSlice(wrappedAB)
	if err := putKEKRecord("device", deviceKEK, wrappedDEK); err != nil {
		return js.Undefined(), keyring.Wrap("keyring/browser: putKEKRecord", err)
	}

	dek, err := unwrapDEK(wrappedDEK, deviceKEK, false)
	if err != nil {
		return js.Undefined(), keyring.Wrap("keyring/browser: unwrap DEK", err)
	}

	cachedDEKHandle = dek
	return dek, nil
}

func unwrapDEK(wrappedDEK []byte, kek js.Value, extractable bool) (js.Value, error) {
	subtle := getSubtle()
	alg := jsObject.New()
	alg.Set("name", "AES-GCM")

	usages := js.Global().Get("Array").New("encrypt", "decrypt")
	wrappedArr := sliceToUint8Array(wrappedDEK)

	unwrapPromise := subtle.Call("unwrapKey", "raw", wrappedArr, kek, "AES-KW", alg, extractable, usages)
	dek, err := awaitPromise(unwrapPromise)
	if err != nil {
		return js.Undefined(), err
	}
	return dek, nil
}

func encryptAESGCM(dek js.Value, iv []byte, plaintext []byte) ([]byte, error) {
	subtle := getSubtle()
	alg := jsObject.New()
	alg.Set("name", "AES-GCM")
	alg.Set("iv", sliceToUint8Array(iv))

	promise := subtle.Call("encrypt", alg, dek, sliceToUint8Array(plaintext))
	cipherAB, err := awaitPromise(promise)
	if err != nil {
		return nil, err
	}
	return arrayBufferToSlice(cipherAB), nil
}

func decryptAESGCM(dek js.Value, iv []byte, ciphertext []byte) ([]byte, error) {
	subtle := getSubtle()
	alg := jsObject.New()
	alg.Set("name", "AES-GCM")
	alg.Set("iv", sliceToUint8Array(iv))

	promise := subtle.Call("decrypt", alg, dek, sliceToUint8Array(ciphertext))
	plainAB, err := awaitPromise(promise)
	if err != nil {
		return nil, keyring.ErrNotFound
	}
	return arrayBufferToSlice(plainAB), nil
}
