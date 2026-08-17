---
PLAN: "feat: dependency-free keyring with four platform backends incl. browser"
TAG: v0.2.0
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 14521747933076742502
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.

# Plan — `tinywasm/keyring` on four environments, with no third-party dependencies

**Execute ALL the stages below, in order.** Each stage is a separate file; open
them one at a time and complete a stage fully — code, tests, docs — before
starting the next.

## 1. What this repository becomes

Today `keyring` is a thin wrapper over `github.com/zalando/go-keyring`, which
drags in `godbus/dbus/v5`, `danieljoos/wincred`, `golang.org/x/sys` and
`al.essio.dev/pkg/shellescape`. None of those compiles to WebAssembly, so the
browser — the platform this ecosystem exists for — has no secret storage at all.

After this plan:

```
keyring/
├── keyring.go            public API — ZERO imports, ZERO backends
├── errors.go             typed error constants — ZERO imports
├── provider.go           Provider interface + Fallback + Ensurer
├── auto/                 OPTIONAL: picks a backend for the build target
├── linux/                Secret Service over D-Bus   → github.com/tinywasm/dbus
├── darwin/               /usr/bin/security           → stdlib only
├── windows/              advapi32.dll via syscall    → stdlib only
├── browser/              WebCrypto + IndexedDB       → syscall/js only
└── tests/
```

`go.mod` ends with exactly two `require`s: `github.com/tinywasm/dbus` (stage 4,
the Linux backend) and `github.com/tinywasm/await` (stage 5, blocking on
WebCrypto promises and IndexedDB requests in the browser backend) — both
in-ecosystem, both zero-dependency themselves.

**The core imports no backend.** The caller injects one:

```go
kr := keyring.NewKeyring("my-app", linux.New())    // explicit
kr := keyring.OpenKeyring("my-app", browser.New()) // explicit, in a browser
kr := auto.OpenKeyring("my-app")                   // "whatever this machine has"
```

`init()`-based registration is deliberately **not** used — see
[stage 1](PLAN_STAGE_1_CORE.md) §"Why injection". Build tags therefore appear in
exactly three places, and only where the compiler forces them: `windows/`
(`syscall.NewLazyDLL` exists nowhere else), `browser/` (`syscall/js` exists only
under `GOOS=js`), and `auto/`, whose only job is to choose.

## 2. THE RULE THAT IS EASIEST TO GET WRONG

> **Only the root package and `browser/` reach the WASM binary.**
> A browser build imports `keyring` and `keyring/browser` and nothing else, so
> `linux/`, `darwin/` and `windows/` are never compiled into it. Their
> **stdlib imports are correct, intentional, and must not be changed**.

You will read, in this ecosystem's other repositories, that stdlib packages are
banned in favour of `tinywasm/fmt`. That rule protects the WASM binary. It does
**not** apply to `linux/`, `darwin/` and `windows/`, which can never run in a
browser. Do **not** "fix" `os/exec`, `net`, `syscall`, `strings` or `errors`
imports in those three folders. Measured precedent: importing `tinywasm/fmt`
into `tinywasm/base64` made the binary **74 KB larger**, not smaller.

Where the rule *does* apply — the root package and `browser/` — it applies
absolutely: **zero imports** in the root, and `syscall/js` only in `browser/`.
Errors are declared as a local comparable string type, never via `errors` or
`tinywasm/fmt`.

## 3. The public API — what changes and what may not

Adopting injection changes the constructors: they take the provider. Everything
a consumer *does* with a `Keyring` stays identical.

```go
// changed — the provider is now a parameter
keyring.NewKeyring(service string, p Provider) (*Keyring, error)
keyring.OpenKeyring(service string, p Provider) *Keyring
keyring.New(p Provider) *KeyManager

// unchanged — no stage may alter these
(*Keyring).Set(key, value string) error
(*Keyring).Get(key string) (string, error)
(*Keyring).Delete(key string) error
(*Keyring).SetLog(fn func(...any))
(*KeyManager).Setup/GetHMACSecret/GetGitHubPAT/Rotate*/IsConfigured/DeleteAll

// removed — mutable package-level state
keyring.SetProvider(p Provider)
keyring.GetProvider() Provider

// new — the platform-choosing convenience layer, with TODAY's signatures
auto.NewKeyring(service string) (*Keyring, error)
auto.OpenKeyring(service string) *Keyring
auto.New() *keyring.KeyManager
```

The 12 call sites in `devflow` and `app` migrate by changing **one import line**
to `keyring "github.com/tinywasm/keyring/auto"`; their call shapes do not move.
`git` needs nothing: `*Keyring` still satisfies its `SecretStore` interface.
Those repositories are out of scope here — stage 1 §10 says what to report.

`tests/keyring_test.go` changes in stage 1: its in-memory provider goes through
the constructor instead of the deleted `SetProvider`. **Every existing
behavioural assertion in it must survive that rewiring** — if a change would
require weakening one, the change is wrong.

## 4. This is a breaking change — write no compatibility code

**Do not write a compatibility layer with `zalando/go-keyring`.** No legacy read
paths, no dual-format decoding, no migration shims. Secrets stored by the
current implementation may become unreadable; the handful of affected developers
re-authenticate once, and this repository does not carry dead branches for them.

If a format detail happens to match the old one, that is because it is the
natural way to write it — not a contract. **No line of code in this plan may
exist whose only justification is reading an old record.** If you find yourself
writing "for backward compatibility" in a comment, delete the code.

## 5. Port the proven code — only the browser is new

`zalando/go-keyring` is MIT-licensed and its native backends have been exercised
against real Keychains, Credential Managers and Secret Service daemons for
years. **Do not reimplement them from a specification.**

Each of stages 2, 3 and 4 appends the original source verbatim and names the one
dependency to replace. Copy the logic; swap the dependency; change nothing else
unless the stage says to.

| Stage | Ported from | Replace |
|---|---|---|
| 1 — Core | `keyring_test.go`, `keyring_mock.go` | package-level funcs → an injected provider |
| 2 — Windows | `keyring_windows.go` | `wincred` → `syscall` + `advapi32.dll` |
| 3 — macOS | `keyring_darwin.go` | `shellescape` → a local `quote` |
| 4 — Linux | `keyring_unix.go` + `secret_service.go` | `godbus` → `tinywasm/dbus` |
| 5 — Browser | **nothing — this is the new code** | — |

**The tests are ported too, and they are the most valuable thing in the
upstream repository.** `keyring_test.go` is not a unit-test file: it is a
**conformance suite** that has been run against real Keychains, Credential
Managers and Secret Service daemons for years. Every case in it is a bug someone
found the hard way — multi-line values, umlauts, a password that merely *looks*
like hex, the empty-service guard on `DeleteAll`.

Stage 1 turns it into `tests/conformance.go`: one exported function that takes a
`Provider` and asserts the whole contract. Then **every backend runs the same
suite** — the in-memory provider always, the native one when the platform is
present, the browser one under `gotest -tinygo`. A backend is not done until it
passes it.

Only one case is dropped: `TestGetSingleLineHex`'s sibling behaviour around the
`go-keyring-encoded:` prefix, since §4 deletes that path. The hex-looking-value
case itself stays — it guards against a naive decoder.

Licensing: MIT into MIT is fine, but `keyring_darwin.go` carries a *"Copyright
2013 Google Inc. — Apache License, Version 2.0"* header that must be **kept
verbatim** in the ported file, and anything derived from `godbus` (BSD-2-Clause)
keeps its notice. Add a `NOTICE` file at the repository root naming all three
and the files they cover.

## 6. Stages

| # | Stage | File | Depends on |
|---|---|---|---|
| 1 | Injected core, errors, `auto` package | [PLAN_STAGE_1_CORE.md](PLAN_STAGE_1_CORE.md) | — |
| 2 | Windows — `advapi32.dll` via `syscall` | [PLAN_STAGE_2_WINDOWS.md](PLAN_STAGE_2_WINDOWS.md) | 1 |
| 3 | macOS — `/usr/bin/security` | [PLAN_STAGE_3_DARWIN.md](PLAN_STAGE_3_DARWIN.md) | 1 |
| 4 | Linux — Secret Service over `tinywasm/dbus` | [PLAN_STAGE_4_LINUX.md](PLAN_STAGE_4_LINUX.md) | 1, `tinywasm/dbus` released |
| 5 | Browser — WebCrypto device key + IndexedDB | [PLAN_STAGE_5_BROWSER.md](PLAN_STAGE_5_BROWSER.md) | 1 |
| 6 | Browser — passkey (WebAuthn PRF) unlock | [PLAN_STAGE_6_PASSKEY.md](PLAN_STAGE_6_PASSKEY.md) | 5, `tinywasm/webauthn` released |

**Stage 6 is severable.** After stage 5 this repository is complete and
releasable: four platforms, zero third-party dependencies. If
`tinywasm/webauthn` is not ready, stop after stage 5 and say so — do not stub,
fake, or inline a partial WebAuthn implementation to make stage 6 look done.

## 7. Definition of done for the whole plan

```bash
# no third-party dependency survives anywhere
grep -rn "zalando\|godbus\|wincred\|shellescape\|golang.org/x/sys" .   # → empty
cat go.mod                                                             # → only tinywasm/dbus

# the core imports no backend, and nothing dispatches by init()
grep -rn "keyring/linux\|keyring/darwin\|keyring/windows\|keyring/browser" *.go  # → empty
grep -rn "func init()" .                                               # → empty

# four platforms build
GOOS=linux go build ./... && GOOS=darwin go build ./... && \
GOOS=windows go build ./... && GOOS=js GOARCH=wasm go build ./...

# the browser binary carries no native backend
go tool nm /tmp/kr.wasm | grep -c "os/exec\|net\."                     # → 0

# the frozen API still satisfies its consumers
gotest
```

## 8. Documentation to update as you go

- `README.md` — replace "Internally uses zalando/go-keyring" with the four
  backends, show the injected constructors and the `auto` shortcut, and add the
  browser example.
- `docs/KEYRING_MANAGEMENT.md` — same correction; it currently names the zalando
  dependency **and** documents the deleted `SetProvider`/`GetProvider` test
  dance (lines 75–77), which must be replaced with constructor injection.
  **This file is in Spanish: keep it in Spanish.**
- `NOTICE` (new, repository root) — the three upstream copyrights from §5 and
  the files each covers.
- `docs/keyring-architecture.mermaid` — redraw with the four backends and the
  browser key hierarchy.
- New `docs/BROWSER_SECURITY.md` — written in stage 5, extended in stage 6.
