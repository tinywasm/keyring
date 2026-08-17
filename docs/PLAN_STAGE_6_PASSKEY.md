← [Stage 5 — Browser](PLAN_STAGE_5_BROWSER.md) | Stage 6 of 6 — **severable**

# Stage 6 — Unlocking the browser keyring with a passkey (WebAuthn PRF)

## Prerequisite, and permission to stop

`github.com/tinywasm/webauthn` must be released first — its plan is at
`https://github.com/tinywasm/webauthn/blob/main/docs/PLAN.md`.

**If it is not available, stop here and report that stage 6 is blocked.** Stages
1–5 leave this repository complete and releasable. Do not stub WebAuthn, do not
inline a partial implementation, and do not mark this stage done.

```bash
go get github.com/tinywasm/webauthn@latest
```

## Goal

Add a second key-encryption key, derived from a passkey, so the data key can be
unlocked only after the user proves themselves with a biometric or PIN. The
`device` KEK from stage 5 stays; this is an **additional** unlock method, never a
replacement.

## 1. The protocol fact that constrains the design

A passkey's private key cannot be read, and JS can only ask it to **sign**.
Signatures are **not deterministic** — they cover a `signCount` that increments
and a random challenge — so no encryption key can be derived from them. Any
implementation that hashes an assertion signature into a key is broken and will
lose user data on the second unlock.

The primitive that works is the **PRF extension** (CTAP2 `hmac-secret`): a fixed
salt in, 32 deterministic bytes out, released only after user verification.

## 2. Two limits that must be visible in the code

**PRF is not universally available.** Synced providers (Apple Passwords, Google
Password Manager) support it, Windows Hello returns PRF values since the
February 2026 update, but Safari on iOS does not pass extension data to external
roaming authenticators — a hardware key there yields nothing. So:

> Enrolment must **probe** and fail cleanly with `ErrPasskeyUnsupported`. The
> keyring keeps working through the `device` KEK. Never degrade silently to a
> different key, and never treat a missing PRF result as an empty salt.

**PRF output is unrecoverable.** Lose the authenticator, lose those 32 bytes
forever. This is precisely why stage 5 built the N-KEK envelope: the `device`
KEK still unwraps the same DEK on that machine. Say this explicitly in the docs
— users who read "passkey-protected" as "backed up" will lose data.

## 3. API — additive only

The frozen `Provider` interface does not change. Add browser-only functions that
consumers call directly:

```go
//go:build wasm

package browser

// EnrollPasskey registers a passkey as an additional unlock method for this
// keyring. It runs a WebAuthn registration ceremony, checks the prf extension
// is enabled, then a second assertion ceremony to obtain the PRF output that
// becomes a key-encryption key wrapping the existing data key.
//
// It blocks and MUST be called from a goroutine started by a user-gesture
// handler. Returns ErrPasskeyUnsupported when the authenticator has no prf.
func EnrollPasskey(opts EnrollOptions) error

// UnlockWithPasskey runs an assertion ceremony and unwraps the data key from
// the passkey KEK. Call it once per session before Get/Set when the caller
// wants user-verified access; without it, the device KEK is used.
func UnlockWithPasskey() error

// PasskeyEnrolled reports whether a passkey KEK exists in this database.
func PasskeyEnrolled() bool

// RevokePasskey deletes the passkey KEK record. The device KEK still unwraps
// the data key, so no secret is lost.
func RevokePasskey() error

type EnrollOptions struct {
	RPID     string // the origin's domain
	RPName   string // shown in the authenticator UI
	UserName string // shown in the account picker
}
```

`Get`/`Set`/`Delete` are unchanged and keep working through the `device` KEK
whether or not a passkey is enrolled. That is the point of the envelope.

## 4. Deriving the KEK from PRF output — exact steps

```
prfOutput (32 bytes, from webauthn.Get with PRFSalt)
   → crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"])
   → crypto.subtle.deriveKey(
         {name: "HKDF", hash: "SHA-256", salt: <hkdfSalt>, info: <infoBytes>},
         hkdfKey,
         {name: "AES-KW", length: 256},
         false,                    // non-extractable
         ["wrapKey", "unwrapKey"])
```

Fixed values — changing any of them orphans every secret wrapped under the old
KEK, so pin them as constants and never "improve" them:

| Value | Definition |
|---|---|
| PRF salt | the 32 bytes of SHA-256 over the ASCII string `tinywasm/keyring/prf/v1` |
| HKDF salt | 32 random bytes generated **once at enrolment** and stored in the `kek` record |
| HKDF info | the ASCII bytes of `tinywasm/keyring/kek/v1` |

The PRF salt is a compile-time constant, so hardcode the 32 bytes as a byte
array with a comment giving the preimage — do not compute SHA-256 at runtime
(that would pull a hash implementation into the binary for no reason).

## 5. Enrolment flow

1. `unlock()` — the DEK must already be available via the `device` KEK. If the
   keyring has never been initialised, initialise it first.
2. `webauthn.Create` with `EnablePRF: true`, `ResidentKey: true`,
   `UserVerification: "required"`. If `PRFEnabled` is false on the result,
   **delete nothing and return `ErrPasskeyUnsupported`** — the credential was
   still created, so say so in the error text: the user will see a passkey in
   their manager that this library refuses to use.
3. `webauthn.Get` with the credential id and `PRFSalt`, obtaining 32 bytes.
   Some authenticators cannot evaluate PRF during creation, which is why this is
   a separate ceremony; do not try to shortcut it.
4. Derive the KEK (§4).
5. Unwrap the DEK **temporarily extractable** with the `device` KEK, wrap it
   with the passkey KEK, discard the extractable handle immediately.
6. Store `{id: "passkey", credentialID, hkdfSalt, wrappedDEK}` in the `kek`
   store. **No CryptoKey is stored** — the passkey KEK is re-derived on every
   unlock and never persists.

The window in step 5 where an extractable DEK handle exists is unavoidable and
should be as short as possible: no `await` on anything else between the unwrap
and the wrap, and no assignment to a package-level variable.

## 6. Unlock flow

1. Read the `passkey` record; absent → `ErrPasskeyNotEnrolled`.
2. `webauthn.Get` with the stored credential id and the PRF salt.
3. Derive the KEK with the stored `hkdfSalt`.
4. `unwrapKey` the stored `wrappedDEK`, non-extractable, and cache it as the
   session DEK.

A `NotAllowedError` from the browser means the user cancelled — surface
`webauthn.ErrAborted` unchanged rather than converting it into a generic
failure. Cancellation is a normal outcome, not an error to retry automatically.

## 7. Errors

```go
const (
	ErrPasskeyUnsupported  Error = "keyring: authenticator does not support the prf extension"
	ErrPasskeyNotEnrolled  Error = "keyring: no passkey enrolled for this keyring"
)
```

## 8. Tests

WebAuthn cannot be driven headlessly without a virtual authenticator, so split
the work honestly:

1. **Pure logic under `gotest -tinygo`**, with `navigator.credentials` stubbed
   in `js.Global()`:
   - a stub returning `prf.enabled === false` makes `EnrollPasskey` return
     `ErrPasskeyUnsupported` and **write nothing** to the `kek` store
   - a stub returning fixed PRF bytes makes enrolment store a `passkey` record
     containing a `credentialID`, an `hkdfSalt` and a `wrappedDEK` — and **no**
     `key` field
   - `UnlockWithPasskey` with the same stub yields a DEK that decrypts a secret
     written before enrolment — the proof that the envelope works
   - the same stub returning **different** PRF bytes fails to unwrap, and the
     error is not swallowed
   - `RevokePasskey` removes the record, and `Get` still works afterwards via
     the device KEK — the "you did not lose your data" guarantee
   - a cancelled ceremony surfaces `webauthn.ErrAborted`
2. **Manual verification** in `docs/PASSKEY_VERIFICATION.md`: Chrome DevTools
   Virtual Authenticator with "supports PRF" enabled, plus one real device.
   List the steps and their expected outcomes. Do not claim these ran if they
   did not.

## 9. Documentation

Extend `docs/BROWSER_SECURITY.md`:

- the updated key hierarchy with two live KEKs
- what the passkey KEK adds (hardware-backed, user-verified) and what it does
  **not** add (it is not a backup; the device KEK is still there)
- the support matrix from §2 with its date, so a future reader knows how stale
  it is
- the "signatures are not deterministic" warning, so nobody reimplements this
  the wrong way later

## 10. Acceptance checklist

```bash
grep -rn "tinywasm/webauthn" go.mod       # → present, alongside tinywasm/dbus and tinywasm/await
grep -rn "\"fmt\"\|\"errors\"\|crypto/" browser/   # → empty
GOOS=js GOARCH=wasm go build ./...
gotest -tinygo
```
