# Browser backend — threat model and key hierarchy

## What the attacker is

**Script running in the origin**: an XSS, or a compromised dependency shipped
into the page. Not a compromised browser, not a compromised OS.

| Property | Achieved? | How |
|---|---|---|
| Secrets are not readable from `localStorage` | ✅ | only ciphertext is stored, and it lives in IndexedDB |
| The encryption key cannot be exported | ✅ | `extractable: false` `CryptoKey`; JS holds a *handle*, never bytes |
| Key material survives a page reload | ✅ | a `CryptoKey` is structured-cloneable into IndexedDB |
| Unlock requires the user to prove themselves | ⚠️ | only with an enrolled passkey (`EnrollPasskey`); the device KEK needs no interaction by design |
| Secrets are unreadable after the tab closes | ❌ | out of scope: the device KEK reopens them silently |
| Script in the origin cannot *use* the key while the page is open | ❌ | **impossible in principle** — see below |

That last row is the honest limit. A non-extractable key stops
**exfiltration**, not **use**. An attacker with script execution can ask the
key to decrypt for as long as the page is open. What they cannot do is take the
key bytes away and use them tomorrow, offline, from another machine. For a
one-shot XSS that is the difference between losing a session and losing the
vault.

## Why not `tinywasm/crypto`

A key held by Go is a `[]byte` in wasm linear memory, and JS can read the whole
of that memory (`new Uint8Array(instance.exports.mem.buffer)`). Non-extractable
key material is therefore unreachable from any Go implementation — not a defect
of `tinywasm/crypto`, a consequence of the wasm memory model. Delegating to
WebCrypto is what buys the property, and it costs zero bytes of cipher code in
the binary.

## Key hierarchy — envelope encryption

```
secret ──AES-GCM──> ciphertext in IndexedDB
                     ↑
              DEK (the only key that touches data)
                     ↑ wrapped independently by N KEKs:
                     ├── device   non-extractable AES-KW CryptoKey in IndexedDB
                     ├── passkey  WebAuthn PRF → HKDF-SHA256 → AES-KW
                     └── recovery PBKDF2(passphrase)          [designed, NOT built]
```

Each KEK stores **its own wrapped copy of the same DEK**. Adding or revoking an
unlock method rewraps one small blob and re-encrypts nothing. The storage
format holds N wrapped copies from the start, because retrofitting that would
mean migrating every user's database.

`RevokePasskey` deletes only the passkey record: the device KEK still unwraps
the same DEK, so **revoking a passkey never loses a secret**.

## Passkeys: what the PRF extension is, and its two limits

A passkey's private key cannot be read, and JS can only ask it to **sign**.
Signatures are *not* deterministic — they cover a `signCount` that increments
and a random challenge — so no encryption key can be derived from them. Any
implementation that hashes an assertion signature into a key is broken and
loses data on the second unlock.

The primitive that works is the **PRF extension** (CTAP2 `hmac-secret`): a
fixed salt in, 32 deterministic bytes out, released only after user
verification. Those bytes go through HKDF-SHA256 into an AES-KW key that wraps
the DEK. The passkey KEK is **never stored** — it is re-derived from the
authenticator on every unlock.

Two limits that shaped this design:

- **PRF is not universally available.** Synced providers (Apple Passwords,
  Google Password Manager) support it and Windows Hello returns PRF values as
  of the February 2026 update, but Safari on iOS does not pass extension data
  to external roaming authenticators. `EnrollPasskey` therefore *probes* and
  fails with `ErrPasskeyUnsupported` rather than degrading silently to some
  other key.
- **PRF output is unrecoverable.** Lose the authenticator, lose those 32 bytes
  forever. This is exactly why the device KEK stays: on that machine, the same
  DEK is still reachable. **A passkey is protection, not a backup.**

## Fixed constants — changing them orphans data

| Value | Definition |
|---|---|
| PRF salt | `SHA-256("tinywasm/keyring/prf/v1")`, hardcoded in `browser/passkey.go` |
| HKDF info | the ASCII bytes of `tinywasm/keyring/kek/v1` |
| HKDF salt | 32 random bytes generated once per enrolment, stored beside the wrapped DEK |

Verify the PRF salt with:

```bash
printf 'tinywasm/keyring/prf/v1' | sha256sum
# 6d35c3fda7627a4073ad57f21fe5f7829babf0080e494e3dcd7e2c15c1cbea32
```

## Operational requirements

- **HTTPS or localhost.** `crypto.subtle` is undefined on insecure origins, and
  the backend reports exactly that rather than a generic failure.
- **Call from a goroutine.** `Set`/`Get`/`Delete`/`EnrollPasskey`/
  `UnlockWithPasskey` block on JS promises via `github.com/tinywasm/await`.
  Calling them from the wasm main function, or directly inside a JS event
  callback, deadlocks the page.
- **Ceremonies need a user gesture.** `EnrollPasskey` and `UnlockWithPasskey`
  must run from a goroutine started by a real user interaction, or the browser
  rejects the ceremony.
