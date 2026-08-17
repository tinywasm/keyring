//go:build wasm

package browser

import (
	"syscall/js"

	"github.com/tinywasm/await"
	"github.com/tinywasm/webauthn"
)

// prfSaltBytes is the fixed input to the authenticator's PRF, and it is what
// makes the derived key reproducible across sessions.
//
// It is SHA-256("tinywasm/keyring/prf/v1"), hardcoded rather than hashed at
// runtime so no hash implementation is linked in for one constant. Verify with:
//
//	printf 'tinywasm/keyring/prf/v1' | sha256sum
//
// CHANGING THESE BYTES ORPHANS EVERY SECRET wrapped under the old passkey KEK.
var prfSaltBytes = []byte{
	0x6d, 0x35, 0xc3, 0xfd, 0xa7, 0x62, 0x7a, 0x40,
	0x73, 0xad, 0x57, 0xf2, 0x1f, 0xe5, 0xf7, 0x82,
	0x9b, 0xab, 0xf0, 0x08, 0x0e, 0x49, 0x4e, 0x3d,
	0xcd, 0x7e, 0x2c, 0x15, 0xc1, 0xcb, 0xea, 0x32,
}

// hkdfInfoBytes separates this derivation from any other use of the same PRF
// output. Fixed for the same reason as the salt.
var hkdfInfoBytes = []byte("tinywasm/keyring/kek/v1")

// EnrollOptions describes the passkey to register as an unlock method.
type EnrollOptions struct {
	RPID     string // the origin's domain, e.g. "app.example.com"
	RPName   string // shown in the authenticator UI
	UserName string // shown in the account picker
}

// PasskeyEnrolled reports whether a passkey KEK exists in this database.
func PasskeyEnrolled() bool {
	rec, err := getKEKRecord("passkey")
	return err == nil && rec != nil && len(rec.WrappedDEK) > 0
}

// RevokePasskey deletes the passkey KEK record. The device KEK still unwraps
// the data key, so no secret is lost.
func RevokePasskey() error {
	db, err := openDB()
	if err != nil {
		return err
	}

	tx := db.Call("transaction", storeKEK, "readwrite")
	store := tx.Call("objectStore", storeKEK)
	req := store.Call("delete", "passkey")
	_, err = await.Request(req)
	return err
}

// EnrollPasskey registers a passkey as an additional unlock method for this
// keyring: a WebAuthn registration ceremony, a check that the prf extension is
// enabled, then an assertion ceremony whose PRF output becomes a
// key-encryption key wrapping the existing data key.
//
// It blocks and MUST be called from a goroutine started by a user-gesture
// handler. Returns ErrPasskeyUnsupported when the authenticator has no prf.
func EnrollPasskey(opts EnrollOptions) error {
	if !webauthn.Available() {
		return ErrPasskeyUnsupported
	}

	// The DEK must already exist under the device KEK: a passkey is an
	// additional way to reach the same key, never a replacement.
	if _, err := ensureKeys(); err != nil {
		return err
	}

	cred, err := webauthn.Create(webauthn.CreateOptions{
		RPID:             opts.RPID,
		RPName:           opts.RPName,
		UserID:           randomBytes(32),
		UserName:         opts.UserName,
		UserDisplayName:  opts.UserName,
		Challenge:        randomBytes(32),
		ResidentKey:      true,
		UserVerification: "required",
		EnablePRF:        true,
	})
	if err != nil {
		return err
	}
	if !cred.PRFEnabled {
		// The credential was still created, so the user now sees a passkey in
		// their manager that this library refuses to use.
		return ErrPasskeyUnsupported
	}

	// A separate assertion is required: several authenticators report prf as
	// enabled at creation but cannot evaluate it until the next ceremony.
	prf, err := evaluatePRF(opts.RPID, cred.ID)
	if err != nil {
		return err
	}

	hkdfSalt := randomBytes(32)
	passkeyKEK, err := derivePasskeyKEK(prf, hkdfSalt)
	if err != nil {
		return err
	}

	// Unwrap the DEK as *temporarily extractable* so it can be re-wrapped under
	// the new KEK. This window is unavoidable; nothing else may await between
	// the unwrap and the wrap, and the extractable handle never escapes here.
	deviceRec, err := getKEKRecord("device")
	if err != nil {
		return err
	}
	tempDEK, err := unwrapDEK(deviceRec.WrappedDEK, deviceRec.Key, true)
	if err != nil {
		return err
	}

	subtle := getSubtle()
	wrapped, err := await.Promise(subtle.Call("wrapKey", "raw", tempDEK, passkeyKEK, "AES-KW"))
	if err != nil {
		return err
	}

	return putKEKRecordFull(&KEKRecord{
		ID:           "passkey",
		Key:          js.Null(), // the passkey KEK is re-derived, never stored
		WrappedDEK:   arrayBufferToSlice(wrapped),
		HKDFSalt:     hkdfSalt,
		CredentialID: cred.ID,
		RPID:         opts.RPID,
	})
}

// UnlockWithPasskey runs an assertion ceremony and unwraps the data key from
// the passkey KEK. Call it once per session before Get/Set when the caller
// wants user-verified access; without it, the device KEK is used.
//
// Blocks, and must be called from a goroutine started by a user gesture.
func UnlockWithPasskey() error {
	rec, err := getKEKRecord("passkey")
	if err != nil || rec == nil || len(rec.HKDFSalt) == 0 || len(rec.CredentialID) == 0 {
		return ErrPasskeyNotEnrolled
	}
	if !webauthn.Available() {
		return ErrPasskeyUnsupported
	}

	prf, err := evaluatePRF(rec.RPID, rec.CredentialID)
	if err != nil {
		return err
	}

	passkeyKEK, err := derivePasskeyKEK(prf, rec.HKDFSalt)
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

// evaluatePRF asks the authenticator for the 32 deterministic bytes bound to
// this credential and prfSaltBytes, released only after user verification.
func evaluatePRF(rpID string, credentialID []byte) ([]byte, error) {
	assertion, err := webauthn.Get(webauthn.GetOptions{
		RPID:             rpID,
		Challenge:        randomBytes(32),
		AllowCredentials: [][]byte{credentialID},
		UserVerification: "required",
		PRFSalt:          prfSaltBytes,
	})
	if err != nil {
		// A cancelled ceremony is a normal outcome: pass webauthn.ErrAborted
		// through unchanged rather than flattening it into a generic failure.
		return nil, err
	}
	if len(assertion.PRFOutput) == 0 {
		// Never fabricate, pad, or fall back to another value: a silent
		// fallback would encrypt data under a key nobody can reproduce.
		return nil, ErrPasskeyUnsupported
	}
	return assertion.PRFOutput, nil
}

// derivePasskeyKEK turns the authenticator's PRF output into a non-extractable
// AES-KW key via HKDF-SHA256.
func derivePasskeyKEK(prfOutput, hkdfSalt []byte) (js.Value, error) {
	subtle := getSubtle()

	importAlg := jsObject.New()
	importAlg.Set("name", "HKDF")
	baseKey, err := await.Promise(subtle.Call("importKey", "raw",
		sliceToUint8Array(prfOutput), importAlg, false,
		js.Global().Get("Array").New("deriveKey")))
	if err != nil {
		return js.Undefined(), err
	}

	hkdfParams := jsObject.New()
	hkdfParams.Set("name", "HKDF")
	hkdfParams.Set("hash", "SHA-256")
	hkdfParams.Set("salt", sliceToUint8Array(hkdfSalt))
	hkdfParams.Set("info", sliceToUint8Array(hkdfInfoBytes))

	targetAlg := jsObject.New()
	targetAlg.Set("name", "AES-KW")
	targetAlg.Set("length", 256)

	return await.Promise(subtle.Call("deriveKey", hkdfParams, baseKey, targetAlg,
		false, js.Global().Get("Array").New("wrapKey", "unwrapKey")))
}

// randomBytes returns n cryptographically random bytes from the browser.
func randomBytes(n int) []byte {
	ua := jsUint8Array.New(n)
	jsCrypto.Call("getRandomValues", ua)
	b := make([]byte, n)
	js.CopyBytesToGo(b, ua)
	return b
}
