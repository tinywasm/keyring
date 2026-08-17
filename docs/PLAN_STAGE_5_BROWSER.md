← [Stage 4 — Linux](PLAN_STAGE_4_LINUX.md) | Stage 5 of 6 | Next → [Stage 6 — Passkey](PLAN_STAGE_6_PASSKEY.md)

# Stage 5 — Browser backend: WebCrypto device key + IndexedDB

## Prerequisite

`github.com/tinywasm/await` must be released before this stage starts — this
package blocks on WebCrypto promises and IndexedDB requests through it rather
than implementing that bridge inline (§5). Its plan is at
`https://github.com/tinywasm/await/blob/main/docs/PLAN.md`. If the module does
not exist yet, **stop and report** — do not inline a copy to unblock this
stage; that recreates the duplication the module exists to remove.

```bash
go get github.com/tinywasm/await@latest
```

## Goal

Give the browser the same `Set`/`Get`/`Delete` contract as the three native
platforms, with key material that **cannot be read out of the page** — even by
script running in the origin.

This stage is the release point: after it, `keyring` works on four platforms
with two in-ecosystem dependencies (`tinywasm/dbus` from stage 4,
`tinywasm/await` here) and no third-party ones.

## Ground rules for this folder — the strict ones

`keyring/browser/` **is** the WASM binary. Everything in [PLAN.md](PLAN.md) §2
applies at full force here:

- **`syscall/js`, the root `keyring` package, and `tinywasm/await` are the only
  permitted imports.** No `fmt`, `errors`, `strings`, `strconv`, `encoding/*`,
  and no other `tinywasm/*` — not even `tinywasm/fmt` to declare an error.
  Measured precedent: that single import cost `tinywasm/base64` 74 KB. `await`
  is the one exception because it was built to this same zero-dependency
  standard for this exact purpose (§5); the root `keyring` package is free
  because it imports nothing itself.
- **No Go crypto.** `crypto/aes`, `crypto/cipher` and `tinywasm/crypto` are all
  forbidden here. The browser's WebCrypto does the work, which is both smaller
  (zero bytes of cipher code in the binary) and stronger (the key can be
  non-extractable, which a Go implementation can never be).
- Every file carries `//go:build wasm`.

## 1. Threat model — write this down before writing code

The attacker is **script running in the origin** (XSS, a compromised
dependency). Against that attacker:

| Property | Achieved? | How |
|---|---|---|
| Secrets are not readable from `localStorage` | ✅ | ciphertext only, in IndexedDB |
| The encryption key cannot be exported | ✅ | `extractable: false` CryptoKey; JS holds a *handle*, never bytes |
| Key material survives a page reload | ✅ | CryptoKey is structured-cloneable into IndexedDB |
| Secrets are unreadable after the tab closes | ❌ | out of scope here; stage 6 adds user-verified unlock |
| An attacker with script access cannot *use* the key while the page is open | ❌ | **impossible in principle** — say so plainly |

That last row is the honest limit: a non-extractable key stops **exfiltration**,
not **use**. Document it in `docs/BROWSER_SECURITY.md` rather than implying more
protection than exists.

## 2. Key hierarchy — build the N-KEK format now

```
secret ──AES-GCM(DEK)──> ciphertext in IndexedDB
                          ↑
                  DEK, wrapped separately by each KEK:
                  ├── "device"   AES-KW, non-extractable, in IndexedDB   ← this stage
                  ├── "passkey"  AES-KW from WebAuthn PRF → HKDF          ← stage 6
                  └── "recovery" AES-KW from PBKDF2(passphrase)           ← NOT built
```

**Only the `device` KEK is implemented in this stage.** But the storage format
must already hold **N wrapped copies keyed by name**, because retrofitting that
later means migrating every user's database. Designing the hole now costs one
extra object store; skipping it is the one decision here that is expensive to
reverse.

Do **not** implement `recovery` in this stage. It needs UX decisions (how the
passphrase is shown, how backup is enforced) that a library with no UI cannot
make.

## 3. IndexedDB schema

Database `tinywasm-keyring`, version `1`, two object stores:

| Store | keyPath | Record |
|---|---|---|
| `kek` | `id` | `{id: "device", key: <CryptoKey>, wrappedDEK: <ArrayBuffer>}` |
| `secrets` | `id` | `{id: "<service>\x00<key>", iv: <ArrayBuffer>, data: <ArrayBuffer>}` |

Notes that matter:

- A `CryptoKey` can be stored **directly** as an IndexedDB value — structured
  clone handles it, and a non-extractable key stays non-extractable across the
  round trip. Do not try to serialise it yourself; `exportKey` on a
  non-extractable key throws, which is the whole point.
- The `secrets` id joins service and key with a NUL byte so
  `("a\x00b", "c")` and `("a", "b\x00c")` cannot collide.
- Version 1 only. If `onupgradeneeded` fires for a higher version, fail with
  `ErrUnavailable` rather than guessing at a migration.

## 4. Cryptographic operations — exact parameters

Use `crypto.subtle` throughout. Parameter drift here produces data that decrypts
on one browser and not another, so treat these as fixed:

**Generate the device KEK** (first run only):

```js
crypto.subtle.generateKey({name: "AES-KW", length: 256}, false, ["wrapKey", "unwrapKey"])
```

`extractable = false`. This handle is stored in IndexedDB and is the root of
trust on this device.

**Generate the DEK** (first run only):

```js
crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"])
```

`extractable = true` — **required**, because `wrapKey` refuses to wrap a
non-extractable key. Wrap it immediately and **drop the extractable handle**;
it must never be stored or kept beyond the enrolment call.

```js
crypto.subtle.wrapKey("raw", dek, deviceKEK, "AES-KW")   // → ArrayBuffer, stored
```

**Unlock the DEK** (every session):

```js
crypto.subtle.unwrapKey("raw", wrappedDEK, deviceKEK, "AES-KW",
                        {name: "AES-GCM"}, false, ["encrypt", "decrypt"])
```

`extractable = false` here. The in-memory DEK for normal operation can never be
exported. Cache this handle in a package-level variable for the life of the page.

**Enrol a second KEK** (stage 6 uses this; provide the seam now):

```js
crypto.subtle.unwrapKey("raw", wrappedDEK, deviceKEK, "AES-KW",
                        {name: "AES-GCM"}, true, ["encrypt", "decrypt"])  // temporarily extractable
crypto.subtle.wrapKey("raw", tempDEK, newKEK, "AES-KW")                   // → second wrapped copy
```

This is why the envelope works: a **new** unlock method can be added without the
raw DEK ever being persisted, and without re-encrypting a single secret.

**Encrypt a value**:

```js
iv = crypto.getRandomValues(new Uint8Array(12))
crypto.subtle.encrypt({name: "AES-GCM", iv: iv}, dek, plaintextBytes)
```

A fresh random 12-byte IV **per write**. Reusing an IV under AES-GCM breaks the
cipher outright — never derive it from the key name, never keep a counter.

## 5. Blocking on promises without deadlocking

Every call above is asynchronous, and the public API is synchronous. Block the
goroutine on `github.com/tinywasm/await`:

```go
import "github.com/tinywasm/await"

result, err := await.Promise(p)          // crypto.subtle.* calls
result, err := await.Request(req)        // IndexedDB requests
```

**Import the module — do not copy its ~35 lines into this package.** An
earlier draft of this plan called for copying the pattern inline to avoid a
dependency, on the reasoning that `tinywasm/jsvalue` pulls in `tinywasm/fmt`
and `tinywasm/model`. That reasoning was sound about `jsvalue` and wrong about
the conclusion: `tinywasm/await` exists specifically because this pattern was
about to be duplicated a fourth and fifth time (`jsvalue`, `indexdb`, this
package, and `tinywasm/webauthn`). It has **zero dependencies** — `syscall/js`
only — so importing it costs what the code you actually call costs, nothing
more. Copying it here would recreate the exact duplication `tinywasm/await`
was built to end, inside the one package in this plan held to the strictest
size discipline.

`go.mod` therefore ends this stage with **two** requires:
`github.com/tinywasm/dbus` (stage 4) and `github.com/tinywasm/await`.

**The caller-facing rule, which must be in the README in bold:** these calls
block, so they must run from a goroutine, never from the WASM main function or
directly inside a JS event callback. Doing so deadlocks the page.

## 6. Byte conversion

`js.CopyBytesToGo` / `js.CopyBytesToJS` move data between `[]byte` and
`Uint8Array`. An `ArrayBuffer` from WebCrypto must be wrapped first:
`js.Global().Get("Uint8Array").New(arrayBuffer)`. Cache the `Uint8Array`
constructor in a package-level variable — looking it up per call is a
measurable cost in TinyGo.

Strings convert with `[]byte(s)` and `string(b)`; UTF-8 is what both sides
expect, so no encoding layer is needed.

## 7. Provider implementation

```go
//go:build wasm

package browser

func New() *Provider

func (p *Provider) Set(service, key, value string) error
func (p *Provider) Get(service, key string) (string, error)
func (p *Provider) Delete(service, key string) error
func (p *Provider) DeleteAll(service string) error
```

`DeleteAll(service)` returns `ErrNotFound` for an empty service (same guard as
every other backend), then opens a cursor over `secrets` and deletes every
record whose id starts with `service + "\x00"`.

`Set`/`Get`/`Delete` each call `unlock()` first, which is idempotent: if the
cached DEK handle is present, return it; otherwise open the database, read the
`device` KEK, unwrap, cache. First ever call also generates and stores both keys.

Availability check, before anything else:

```go
if !js.Global().Get("crypto").Truthy() ||
   !js.Global().Get("crypto").Get("subtle").Truthy() ||
   !js.Global().Get("indexedDB").Truthy() {
	return ErrUnavailable
}
```

`crypto.subtle` is **undefined on insecure origins** — a page served over plain
HTTP gets `ErrUnavailable`, and the error message must say so, because that is
the failure a developer will actually hit:
`` `keyring: crypto.subtle unavailable — the page must be served over HTTPS or from localhost` ``

## 8. Files to create

| File | Contents |
|---|---|
| `browser/provider.go` | `Provider`, the four methods, availability check |
| `browser/keys.go` | KEK/DEK generation, wrap, unwrap, the enrolment seam |
| `browser/db.go` | IndexedDB open, upgrade, get/put/delete, cursor — calls `await.Request` |
| `browser/errors.go` | browser-specific sentinels only; the shared ones come from the root package |

No `await.go` file: the async bridge is `github.com/tinywasm/await`, imported,
not written here.

## 9. Tests

Run with `gotest -tinygo`, which is what actually exercises the WASM target —
plain `gotest` compiles this package with the Go toolchain and would not catch
TinyGo-specific breakage.

**Start with the conformance suite from stage 1 §8b.** This backend is new code,
which makes running the same battle-tested contract as the three native ones
more important here, not less:

```go
//go:build wasm

func TestBrowserConformance(t *testing.T) {
	RunConformance(t, browser.New(), true)   // true: no hard size limit
}
```

That covers the round trip, isolation between services, `ErrNotFound`, delete
semantics, the `DeleteAll("")` guard, multi-line values and non-ASCII. Then add
the cases that are specific to this backend and have no upstream equivalent:

1. **Persistence across "reloads"**: clear the cached DEK handle, call `Get`
   again, assert the value still decrypts — this is the test that proves the
   wrapped DEK and the stored CryptoKey actually work.
2. **The DEK is not extractable**: call `crypto.subtle.exportKey("raw", dek)`
   on the cached handle and assert it **rejects**. This is the security claim of
   the whole stage; assert it, do not assume it.
3. **Distinct IVs**: write the same value twice and assert the two stored `iv`
   fields differ.
4. **No plaintext at rest**: after `Set("svc","k","hunter2")`, read the raw
   IndexedDB record and assert the bytes `hunter2` appear nowhere in it.

Between tests, delete the database so state does not leak across cases.

## 10. Size budget — measure, do not assume

Record the numbers in `docs/BROWSER_SECURITY.md`:

```bash
tinygo build -o /tmp/before.wasm -target wasm ./testdata/wasmprobe   # before this stage
tinygo build -o /tmp/after.wasm  -target wasm ./testdata/wasmprobe   # after
stat -c '%s %n' /tmp/before.wasm /tmp/after.wasm
```

`testdata/wasmprobe` is a `main` package that calls `OpenKeyring("probe")` and
one `Get`. Expected growth is small — this package is JS interop, not
algorithms. **If it exceeds 15 KB, stop and find the import that caused it**
before continuing; that is exactly the symptom the `tinywasm/base64` lesson
describes.

## 11. Documentation

Write `docs/BROWSER_SECURITY.md`:

- the threat model table from §1, including the honest ❌ rows
- the key hierarchy diagram from §2
- why a Go AES implementation was rejected (non-extractability is unreachable
  from Go)
- the goroutine/blocking rule
- the HTTPS requirement
- the measured size delta

Update `README.md` with a browser example and update
`docs/keyring-architecture.mermaid` to show four backends.

## 12. Acceptance checklist

```bash
grep -rn "\"fmt\"\|\"errors\"\|\"strings\"\|crypto/" browser/              # → empty
grep -rn "tinywasm/" browser/ | grep -v "tinywasm/keyring\"\|tinywasm/await\""  # → empty
GOOS=js GOARCH=wasm go build ./...
gotest -tinygo
go tool nm /tmp/after.wasm | grep -c "os/exec\|net\."                      # → 0
```
