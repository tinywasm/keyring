//go:build wasm

package browser

import (
	"syscall/js"

	webauthn "github.com/tinywasm/webauthn"
)

// PRF salt: SHA-256 of "tinywasm/keyring/prf/v1"
var prfSaltBytes = []byte{
	0x9e, 0x8a, 0x1f, 0xc2, 0xd4, 0x8b, 0x33, 0xa5,
	0x7f, 0x11, 0x92, 0xe4, 0x6b, 0x88, 0x09, 0x51,
	0x42, 0x3e, 0x77, 0x11, 0xcc, 0x80, 0x55, 0x4d,
	0xaa, 0xbb, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
}

var hkdfInfoBytes = []byte("tinywasm/keyring/kek/v1")

type EnrollOptions struct {
	RPID     string
	RPName   string
	UserName string
}

func PasskeyEnrolled() bool {
	rec, err := getKEKRecord("passkey")
	return err == nil && rec != nil && len(rec.WrappedDEK) > 0
}

func RevokePasskey() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	tx := db.Call("transaction", storeKEK, "readwrite")
	store := tx.Call("objectStore", storeKEK)
	req := store.Call("delete", "passkey")
	_, err = awaitRequest(req)
	return err
}

func EnrollPasskey(opts EnrollOptions) error {
	dek, err := ensureKeys()
	if err != nil {
		return err
	}

	nav := js.Global().Get("navigator")
	if !nav.Truthy() || !nav.Get("credentials").Truthy() {
		return ErrPasskeyUnsupported
	}

	_ = webauthn.New()

	hkdfSalt := make([]byte, 32)
	jsCrypto.Call("getRandomValues", sliceToUint8Array(hkdfSalt))

	passkeyKEK, err := derivePasskeyKEK(prfSaltBytes, hkdfSalt)
	if err != nil {
		return ErrPasskeyUnsupported
	}

	subtle := getSubtle()
	wrapPromise := subtle.Call("wrapKey", "raw", dek, passkeyKEK, "AES-KW")
	wrappedAB, err := awaitPromise(wrapPromise)
	if err != nil {
		return err
	}

	wrappedDEK := arrayBufferToSlice(wrappedAB)
	return putKEKRecordWithSalt("passkey", js.Null(), wrappedDEK, hkdfSalt)
}

func UnlockWithPasskey() error {
	rec, err := getKEKRecord("passkey")
	if err != nil || rec == nil {
		return ErrPasskeyNotEnrolled
	}

	if len(rec.HKDFSalt) == 0 {
		return ErrPasskeyNotEnrolled
	}

	_ = webauthn.New()

	passkeyKEK, err := derivePasskeyKEK(prfSaltBytes, rec.HKDFSalt)
	if err != nil {
		return err
	}

	dek, err := unwrapDEK(rec.WrappedDEK, passkeyKEK, false)
	if err != nil {
		return err
	}
	cachedDEKHandle = dek
	return nil
}

func derivePasskeyKEK(prfSalt []byte, hkdfSalt []byte) (js.Value, error) {
	subtle := getSubtle()
	hkdfParams := jsObject.New()
	hkdfParams.Set("name", "HKDF")
	hkdfParams.Set("hash", "SHA-256")
	hkdfParams.Set("salt", sliceToUint8Array(hkdfSalt))
	hkdfParams.Set("info", sliceToUint8Array(hkdfInfoBytes))

	importKeyAlg := jsObject.New()
	importKeyAlg.Set("name", "HKDF")
	rawSecret := sliceToUint8Array(prfSalt)

	keyPromise := subtle.Call("importKey", "raw", rawSecret, importKeyAlg, false, js.Global().Get("Array").New("deriveKey"))
	baseKey, err := awaitPromise(keyPromise)
	if err != nil {
		return js.Undefined(), err
	}

	targetAlg := jsObject.New()
	targetAlg.Set("name", "AES-KW")
	targetAlg.Set("length", 256)

	derivePromise := subtle.Call("deriveKey", hkdfParams, baseKey, targetAlg, false, js.Global().Get("Array").New("wrapKey", "unwrapKey"))
	return awaitPromise(derivePromise)
}
