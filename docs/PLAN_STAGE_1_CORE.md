Stage 1 of 6 | Next → [Stage 2 — Windows](PLAN_STAGE_2_WINDOWS.md)

# Stage 1 — Injected backends, typed errors, zero-import core

## Goal

Turn the root package into a **backend-agnostic core that imports nothing and
decides nothing**. The caller chooses its provider and passes it in. A separate,
optional `auto` package makes that choice for multiplatform CLIs.

No backend is implemented in this stage: the four packages are created as
skeletons returning `ErrUnsupported`, so every `GOOS` compiles from here on and
stages 2–5 become independently verifiable. `zalando/go-keyring` is removed from
`go.mod` **in this stage**.

## Why injection, and not `init()` registration

The obvious design is a `register_linux.go` per platform doing
`init() { currentProvider = linux.New() }`. It is the wrong one, for the reason
already recorded in this ecosystem's `deploy` plan:

> *Registration via `init()` inside the package is the inverse of injection: the
> package depends on its backends instead of the backends depending on it, and
> every consumer links every backend whether or not it will ever use one.*

Three concrete consequences here:

1. **`keyring` would import `keyring/linux`**, which imports `tinywasm/dbus`,
   which opens Unix sockets — inside a module whose whole point is to be small
   in a browser.
2. **The provider would be a mutable package-level variable**, so tests cannot
   run in parallel and must remember to restore it.
3. **Build tags would become the dispatch mechanism** instead of what they are:
   a compiler constraint that applies to exactly two packages.

After this stage, build tags survive in **two packages only** — `windows/`
(uses `syscall.NewLazyDLL`, which exists nowhere else) and `browser/` (uses
`syscall/js`, which exists only under `GOOS=js`) — plus the `auto` package,
whose entire job is to choose. `linux/` and `darwin/` carry no tags at all: they
are simply never imported by a browser build.

## Files after this stage

| File | Build tag | Imports |
|---|---|---|
| `keyring.go` | none | **none** |
| `errors.go` | none | **none** |
| `provider.go` | none | **none** |
| `manager.go` | none | **none** |
| `auto/auto.go` | none | `keyring` |
| `auto/auto_linux.go` | `//go:build linux` | `keyring/linux` |
| `auto/auto_darwin.go` | `//go:build darwin` | `keyring/darwin` |
| `auto/auto_windows.go` | `//go:build windows` | `keyring/windows` |
| `auto/auto_wasm.go` | `//go:build wasm` | `keyring/browser` |
| `auto/auto_other.go` | `//go:build !linux && !darwin && !windows && !wasm` | `keyring` |
| `linux/`, `darwin/` | none | (stage 3 / 4) |
| `windows/` | `//go:build windows` | (stage 2) |
| `browser/` | `//go:build wasm` | (stage 5) |
| `tests/conformance.go` | none | the suite every backend must pass (§8b) |
| `tests/mem.go` | none | the in-memory provider (§8a) |
| `tests/keyring_test.go` | none | API-level tests (§8c) |

## 1. `errors.go` — new file, zero imports

```go
package keyring

// Error is the error type of this package. It is a comparable string so
// callers can use errors.Is / == without this package importing "errors".
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrNotFound is returned when the key has no value in this service.
	ErrNotFound Error = "keyring: secret not found"
	// ErrUnsupported is returned by the fallback backend on platforms with no
	// credential store.
	ErrUnsupported Error = "keyring: no credential store on this platform"
	// ErrTooBig is returned when the value exceeds the backend's limit.
	ErrTooBig Error = "keyring: value too large for the platform credential store"
	// ErrUnavailable is returned when a backend exists but cannot be reached
	// (no D-Bus session, locked keychain, storage blocked by the browser).
	ErrUnavailable Error = "keyring: credential store unavailable"
	// ErrNoProvider is returned when a Keyring is built with a nil provider.
	ErrNoProvider Error = "keyring: no provider injected"
)
```

**Backends return these sentinels directly.** With injection there is no import
cycle — `keyring/linux` imports `keyring`, and `keyring` imports nothing — so
each backend uses `keyring.ErrNotFound` and no error-translation layer exists
anywhere. (An earlier draft of this plan called for per-backend sentinel copies
and a mapping adapter; injection deletes that entire problem.)

One helper for adding context without `fmt`:

```go
// Wrap returns an error whose message is prefix + ": " + err.Error(), and whose
// Unwrap returns err so errors.Is still matches the sentinel. Exported because
// the backend packages use it.
func Wrap(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return &wrapped{prefix: prefix, err: err}
}

type wrapped struct {
	prefix string
	err    error
}

func (w *wrapped) Error() string { return w.prefix + ": " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }
```

## 2. `provider.go` — interface and fallback, no registry

Keep the `Provider` interface **exactly as it is today** (`Set`, `Get`,
`Delete`, `DeleteAll`, all taking `service` first).

**Delete `currentProvider`, `SetProvider` and `GetProvider`.** The mutable
package-level provider is gone; a `Keyring` holds its own. Tests inject through
the constructor instead, which is what makes them parallel-safe.

Add the fallback as an exported type, since `auto` returns it on unknown
platforms:

```go
// Fallback answers every call with ErrUnsupported. It is what auto.Provider()
// returns on platforms with no credential store.
type Fallback struct{}

func (Fallback) Set(service, user, password string) error { return ErrUnsupported }
func (Fallback) Get(service, user string) (string, error) { return "", ErrUnsupported }
func (Fallback) Delete(service, user string) error        { return ErrUnsupported }
func (Fallback) DeleteAll(service string) error           { return ErrUnsupported }
```

And the optional capability that replaces the Linux installer in the root:

```go
// Ensurer is implemented by backends that can repair their own prerequisites
// (install packages, start a daemon). NewKeyring calls it when the initial
// probe fails. Backends that cannot self-repair simply do not implement it.
type Ensurer interface {
	Ensure(log func(...any)) error
}
```

## 3. `keyring.go` — the provider becomes a field

```go
package keyring

// Keyring provides scoped credential storage through an injected backend.
// The service name is a namespace: the same key under different services never
// collides, so one process can hold secrets for several apps.
type Keyring struct {
	service  string
	provider Provider
	log      func(...any)
}

// NewKeyring creates a Keyring scoped to service over provider p, and verifies
// the backend actually works — asking it to repair itself when it implements
// Ensurer.
//
// Callers that do not care which backend they get can use
// github.com/tinywasm/keyring/auto, which picks one for the target platform.
func NewKeyring(service string, p Provider) (*Keyring, error)

// OpenKeyring creates a Keyring without probing the backend: nothing is touched
// until the first Get/Set/Delete. Use it when the store is only needed
// conditionally (session recovery) or in flows that may legitimately run
// without one (CI with GH_TOKEN).
func OpenKeyring(service string, p Provider) *Keyring

func (k *Keyring) SetLog(fn func(...any))
func (k *Keyring) Set(key, value string) error
func (k *Keyring) Get(key string) (string, error)
func (k *Keyring) Delete(key string) error
```

`Set`/`Get`/`Delete` delegate to `k.provider` instead of the old global. A nil
provider returns `ErrNoProvider` from every method rather than panicking —
including from `OpenKeyring`, which must not panic at construction time.

Replace `ensureKeyringAvailable` with:

```go
// ensureAvailable probes the backend with a throwaway write and, if that fails,
// asks the backend to repair itself when it knows how.
func (k *Keyring) ensureAvailable() error {
	const probeKey = "keyring_test_probe"

	if err := k.provider.Set(k.service, probeKey, "test"); err == nil {
		k.provider.Delete(k.service, probeKey)
		return nil
	}

	e, ok := k.provider.(Ensurer)
	if !ok {
		return ErrUnavailable
	}
	if err := e.Ensure(k.log); err != nil {
		return err
	}

	if err := k.provider.Set(k.service, probeKey, "test"); err != nil {
		return Wrap("keyring: still unavailable after repair", err)
	}
	k.provider.Delete(k.service, probeKey)
	return nil
}
```

**Delete from `keyring.go`** — these move to `linux/` in stage 4:

- `tryInstallKeyring` (the apt/dnf/pacman table)
- `startKeyringService` (the `gnome-keyring-daemon` launcher)
- the `runtime.GOOS != "linux"` branch
- every import

Acceptance: `grep -n "import" keyring.go` → no import block; `grep -rn
"tryInstallKeyring\|startKeyringService" .` → matches only under `linux/`.

The long manual-install message must not be lost. It moves verbatim into
`linux/` as a constant:

```
could not install keyring. Install manually:
  Debian/Ubuntu: sudo apt install gnome-keyring libsecret-1-0
  Fedora: sudo dnf install gnome-keyring libsecret
  Arch: sudo pacman -S gnome-keyring libsecret
```

## 4. `manager.go` — takes a provider too

`New()` becomes `New(p Provider) *KeyManager`, building its inner `Keyring` with
`OpenKeyring(ServiceName, p)`. Everything else — `ServiceName`, `HMACSecretKey`,
`GitHubPATKey`, and every method — stays exactly as it is, with the five
`fmt.Errorf` wraps replaced by `Wrap`:

| Before | After |
|---|---|
| `fmt.Errorf("failed to store HMAC secret: %w", err)` | `Wrap("failed to store HMAC secret", err)` |
| `fmt.Errorf("failed to store GitHub PAT: %w", err)` | `Wrap("failed to store GitHub PAT", err)` |
| `fmt.Errorf("HMAC secret not found in keyring: %w", err)` | `Wrap("HMAC secret not found in keyring", err)` |
| `fmt.Errorf("GitHub PAT not found in keyring: %w", err)` | `Wrap("GitHub PAT not found in keyring", err)` |

The Spanish doc comments in `manager.go` stay in Spanish; do not translate them.

## 5. `auto/` — the only package that chooses

This package exists so a multiplatform CLI does not grow a build-tagged file of
its own. It is **optional**: a browser application never imports it, and injects
`browser.New()` directly.

`auto/auto.go` — no build tag:

```go
// Package auto picks the credential backend for the platform it is built for.
//
// It exists for multiplatform CLIs that just want "whatever this machine has".
// Code that knows its environment should skip it and inject the backend
// directly — a browser application imports keyring/browser, not this package.
package auto

import "github.com/tinywasm/keyring"

// Keyring is an alias so callers need only this import.
type Keyring = keyring.Keyring

// NewKeyring is keyring.NewKeyring with the platform's provider already chosen.
func NewKeyring(service string) (*Keyring, error) {
	return keyring.NewKeyring(service, Provider())
}

// OpenKeyring is keyring.OpenKeyring with the platform's provider already chosen.
func OpenKeyring(service string) *Keyring {
	return keyring.OpenKeyring(service, Provider())
}

// New is keyring.New with the platform's provider already chosen.
func New() *keyring.KeyManager { return keyring.New(Provider()) }
```

`Provider()` is declared once per platform, each in its own tagged file:

```go
//go:build linux

package auto

import (
	"github.com/tinywasm/keyring"
	"github.com/tinywasm/keyring/linux"
)

// Provider returns the Secret Service backend.
func Provider() keyring.Provider { return linux.New() }
```

The same shape for `darwin`, `windows` and `browser`. `auto_other.go` returns
`keyring.Fallback{}`.

**These five files are the only place in the repository where a platform is
chosen.** Note that `NewKeyring`, `OpenKeyring` and `New` keep the exact
signatures they have today, so a consumer migrates by changing one import line:

```go
// before
import "github.com/tinywasm/keyring"
// after
import keyring "github.com/tinywasm/keyring/auto"
```

Verify that claim rather than assuming it — see §8.

## 6. Backend skeletons

Create `linux/`, `darwin/`, `windows/` and `browser/`, each with a `New()`
constructor and a provider whose four methods return `keyring.ErrUnsupported`.
Stages 2–5 fill in the bodies. `windows/` carries `//go:build windows` and
`browser/` carries `//go:build wasm` from the start; `linux/` and `darwin/`
carry no tag.

## 7. Remove the dependency

```bash
go mod edit -droprequire github.com/zalando/go-keyring
go mod tidy
```

`go.mod` must end with **no `require` block at all** after this stage
(`tinywasm/dbus` arrives in stage 4). Delete `go.sum` if it ends up empty.

Acceptance: `grep -rn "zalando" .` → empty, including `README.md` and
`docs/KEYRING_MANAGEMENT.md`, whose "Internamente usa zalando/go-keyring" line
is replaced with a sentence naming the four backends (in Spanish, in that file).

## 8. Tests — build the conformance suite

This stage produces the harness every later stage is graded against. Three
pieces, all under `tests/`:

### 8a. `tests/mem.go` — the in-memory provider, ported

Port `keyring_mock.go` (appendix B). It is this repository's existing
`memProvider` plus one thing the existing one lacks: an **injectable error**, so
a test can make the backend fail on demand. Export it, because stages 2–5 use it
as the control case:

```go
// MemProvider is an in-memory Provider for tests. Err, when non-nil, is
// returned by every method — use it to drive failure paths.
type MemProvider struct {
	store map[string]map[string]string
	Err   error
}

func NewMemProvider() *MemProvider
```

### 8b. `tests/conformance.go` — the ported suite, parameterised

Port `keyring_test.go` (appendix A) into **one exported function** that any
backend can be run through:

```go
// RunConformance asserts the full Provider contract against p. Every backend
// must pass it: the in-memory provider, each native backend on its own
// platform, and the browser backend under TinyGo.
//
// skipTooBig is true for backends with no size limit (Linux, in-memory), where
// the oversized-value case does not apply.
func RunConformance(t *testing.T, p keyring.Provider, skipTooBig bool)
```

Every case from the original, ported one-to-one from package-level functions to
methods on `p`, each as its own `t.Run` subtest:

| Case | What it protects |
|---|---|
| `Set` | the happy path |
| `SetTooLong` | a 10 002-byte value → `ErrTooBig` on Windows and macOS |
| `GetMultiLine` | **the reason macOS encodes values at all** |
| `GetUmlaut` | non-ASCII survives the round trip |
| `GetSingleLineHex` | a value that merely *looks* hex-encoded is not mangled |
| `Get` | round trip |
| `GetNonExisting` | `ErrNotFound`, not an empty string |
| `Delete` | removal works |
| `DeleteNonExisting` | `ErrNotFound` |
| `DeleteAll` | removes every key of the service, and is idempotent |
| `DeleteAllEmptyService` | **an empty service must not wipe other services** |

Two deliberate changes while porting:

- `err != ErrNotFound` becomes `errors.Is(err, keyring.ErrNotFound)`, so wrapped
  errors still match.
- Each subtest uses a **unique service name** (`t.Name()`), so a backend that
  really touches the OS does not leak state between cases or between runs.

Drop nothing else. In particular do **not** drop `GetSingleLineHex` — §"Drop the
legacy decoding path" in stage 3 removes the `go-keyring-encoded:` *read path*,
not the guarantee that a hex-looking password round-trips intact.

### 8c. `tests/keyring_test.go` — the API-level tests

The existing file changes: its provider goes through the constructor instead of
the deleted `SetProvider`. Keep every existing behavioural assertion. Add
`RunConformance(t, NewMemProvider(), true)` and then:

1. **A nil provider yields `ErrNoProvider`** from `Set`, `Get` and `Delete`, and
   `OpenKeyring(service, nil)` does not panic.
2. **`Ensure` runs exactly once when the probe fails.** Inject a provider whose
   `Set` fails until `Ensure` has run and that counts `Ensure` calls; assert
   `NewKeyring` succeeds and the count is 1.
3. **`Ensure` never runs when the probe succeeds** — count is 0.
4. **A backend without `Ensurer` yields `ErrUnavailable`**, exactly that
   sentinel, no panic.
5. **`OpenKeyring` never probes.** Inject a provider that fails the test if any
   method is called; assert none was.
6. **Two keyrings with different providers do not interfere.** Build two, each
   with its own `memProvider`, write the same key in both, assert the values are
   independent. This is the test that proves the global is really gone — and it
   must pass under `t.Parallel()`.
7. **`Fallback` returns `ErrUnsupported`** from all four methods.
8. **The `auto` drop-in claim.** In a separate test file under `tests/`, import
   `keyring "github.com/tinywasm/keyring/auto"` and call `OpenKeyring("probe")`
   and `NewKeyring("probe")` with the exact call shapes `devflow` uses. This
   compiling **is** the assertion; the test itself may skip on a machine with no
   keyring.

Run with `gotest`.

## 9. Acceptance checklist

```bash
grep -n "^import\|^\t\"" keyring.go errors.go provider.go manager.go   # → empty
grep -rn "SetProvider\|GetProvider\|currentProvider" .                  # → empty
grep -rln "go:build" . | grep -v auto/ | grep -v windows/ | grep -v browser/   # → empty
grep -rn "zalando" .                                                    # → empty
grep -c require go.mod                                                  # → 0
GOOS=linux go build ./... && GOOS=darwin go build ./... && \
GOOS=windows go build ./... && GOOS=js GOARCH=wasm go build ./...
gotest
```

## 10. Consumers — report, do not edit

`devflow` (11 call sites), `app` (1) and `git` (through its `SecretStore`
interface) live in other repositories and are **out of scope for this plan**.
Record in the PR description the one-line import change they need:

```go
import keyring "github.com/tinywasm/keyring/auto"
```

`git` needs no change at all: `*Keyring` still satisfies `SecretStore`.

---

## Appendix A — source to port: `keyring_test.go`

From `github.com/zalando/go-keyring@v0.2.6`, MIT. This is the conformance
suite of §8b. Port every case; convert the package-level `Set`/`Get`/`Delete`
calls into calls on the injected `p Provider`, use `errors.Is` instead of
`==`, and give each subtest a unique service name derived from `t.Name()`.

Note `TestSetTooLong` branches on `runtime.GOOS`. In the ported version that
becomes the `skipTooBig bool` parameter — the suite must not import `runtime`
to decide what it is testing.

```go
package keyring

import (
	"runtime"
	"strings"
	"testing"
)

const (
	service  = "test-service"
	user     = "test-user"
	password = "test-password"
)

// TestSet tests setting a user and password in the keyring.
func TestSet(t *testing.T) {
	err := Set(service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}
}

func TestSetTooLong(t *testing.T) {
	extraLongPassword := "ba" + strings.Repeat("na", 5000)
	err := Set(service, user, extraLongPassword)

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// should fail on those platforms
		if err != ErrSetDataTooBig {
			t.Errorf("Should have failed, got: %s", err)
		}
	}
}

// TestGetMultiline tests getting a multi-line password from the keyring
func TestGetMultiLine(t *testing.T) {
	multilinePassword := `this password
has multiple
lines and will be
encoded by some keyring implementiations
like osx`
	err := Set(service, user, multilinePassword)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := Get(service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if multilinePassword != pw {
		t.Errorf("Expected password %s, got %s", multilinePassword, pw)
	}
}

// TestGetMultiline tests getting a multi-line password from the keyring
func TestGetUmlaut(t *testing.T) {
	umlautPassword := "at least on OSX üöäÜÖÄß will be encoded"
	err := Set(service, user, umlautPassword)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := Get(service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if umlautPassword != pw {
		t.Errorf("Expected password %s, got %s", umlautPassword, pw)
	}
}

// TestGetSingleLineHex tests getting a single line hex string password from the keyring.
func TestGetSingleLineHex(t *testing.T) {
	hexPassword := "abcdef123abcdef123"
	err := Set(service, user, hexPassword)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := Get(service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if hexPassword != pw {
		t.Errorf("Expected password %s, got %s", hexPassword, pw)
	}
}

// TestGet tests getting a password from the keyring.
func TestGet(t *testing.T) {
	err := Set(service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := Get(service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if password != pw {
		t.Errorf("Expected password %s, got %s", password, pw)
	}
}

// TestGetNonExisting tests getting a secret not in the keyring.
func TestGetNonExisting(t *testing.T) {
	_, err := Get(service, user+"fake")
	if err != ErrNotFound {
		t.Errorf("Expected error ErrNotFound, got %s", err)
	}
}

// TestDelete tests deleting a secret from the keyring.
func TestDelete(t *testing.T) {
	err := Delete(service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}
}

// TestDeleteNonExisting tests deleting a secret not in the keyring.
func TestDeleteNonExisting(t *testing.T) {
	err := Delete(service, user+"fake")
	if err != ErrNotFound {
		t.Errorf("Expected error ErrNotFound, got %s", err)
	}
}

// TestDeleteAll tests deleting all secrets for a given service.
func TestDeleteAll(t *testing.T) {
	// Set up multiple secrets for the same service
	err := Set(service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	err = Set(service, user+"2", password+"2")
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	// Delete all secrets for the service
	err = DeleteAll(service)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	// Verify that all secrets for the service are deleted
	_, err = Get(service, user)
	if err != ErrNotFound {
		t.Errorf("Expected error ErrNotFound, got %s", err)
	}

	_, err = Get(service, user+"2")
	if err != ErrNotFound {
		t.Errorf("Expected error ErrNotFound, got %s", err)
	}

	// Verify that DeleteAll on an empty service doesn't cause an error
	err = DeleteAll(service)
	if err != nil {
		t.Errorf("Should not fail on empty service, got: %s", err)
	}
}

// TestDeleteAll with empty service name
func TestDeleteAllEmptyService(t *testing.T) {
	err := Set(service, user, password)

	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}
	_ = DeleteAll("")
	_, err = Get(service, user)
	if err == ErrNotFound {
		t.Errorf("Should not have deleted secret from another service")
	}
}
```

## Appendix B — source to port: `keyring_mock.go`

Same origin and licence. Becomes `tests/mem.go`: exported, with `Err` as an
exported field so failure paths can be driven from any stage.

```go
package keyring

type mockProvider struct {
	mockStore map[string]map[string]string
	mockError error
}

// Set stores user and pass in the keyring under the defined service
// name.
func (m *mockProvider) Set(service, user, pass string) error {
	if m.mockError != nil {
		return m.mockError
	}
	if m.mockStore == nil {
		m.mockStore = make(map[string]map[string]string)
	}
	if m.mockStore[service] == nil {
		m.mockStore[service] = make(map[string]string)
	}
	m.mockStore[service][user] = pass
	return nil
}

// Get gets a secret from the keyring given a service name and a user.
func (m *mockProvider) Get(service, user string) (string, error) {
	if m.mockError != nil {
		return "", m.mockError
	}
	if b, ok := m.mockStore[service]; ok {
		if v, ok := b[user]; ok {
			return v, nil
		}
	}
	return "", ErrNotFound
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (m *mockProvider) Delete(service, user string) error {
	if m.mockError != nil {
		return m.mockError
	}
	if m.mockStore != nil {
		if _, ok := m.mockStore[service]; ok {
			if _, ok := m.mockStore[service][user]; ok {
				delete(m.mockStore[service], user)
				return nil
			}
		}
	}
	return ErrNotFound
}

// DeleteAll deletes all secrets for a given service
func (m *mockProvider) DeleteAll(service string) error {
	if m.mockError != nil {
		return m.mockError
	}
	delete(m.mockStore, service)
	return nil
}

// MockInit sets the provider to a mocked memory store
func MockInit() {
	provider = &mockProvider{}
}

// MockInitWithError sets the provider to a mocked memory store
// that returns the given error on all operations
func MockInitWithError(err error) {
	provider = &mockProvider{mockError: err}
}
```

## Appendix C — reference: `keyring_mock_test.go`

Tests of the mock itself. Not required, but read it: it shows the error
injection pattern the `Ensure` tests in §8c need.

```go
package keyring

import (
	"errors"
	"testing"
)

// TestSet tests setting a user and password in the keyring.
func TestMockSet(t *testing.T) {
	mp := mockProvider{}
	err := mp.Set(service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}
}

// TestGet tests getting a password from the keyring.
func TestMockGet(t *testing.T) {
	mp := mockProvider{}
	err := mp.Set(service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	pw, err := mp.Get(service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	if password != pw {
		t.Errorf("Expected password %s, got %s", password, pw)
	}
}

// TestGetNonExisting tests getting a secret not in the keyring.
func TestMockGetNonExisting(t *testing.T) {
	mp := mockProvider{}

	_, err := mp.Get(service, user+"fake")
	assertError(t, err, ErrNotFound)
}

// TestDelete tests deleting a secret from the keyring.
func TestMockDelete(t *testing.T) {
	mp := mockProvider{}

	err := mp.Set(service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	err = mp.Delete(service, user)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}
}

// TestDeleteNonExisting tests deleting a secret not in the keyring.
func TestMockDeleteNonExisting(t *testing.T) {
	mp := mockProvider{}

	err := mp.Delete(service, user+"fake")
	assertError(t, err, ErrNotFound)
}

func TestMockWithError(t *testing.T) {
	mp := mockProvider{mockError: errors.New("mock error")}

	err := mp.Set(service, user, password)
	assertError(t, err, mp.mockError)

	_, err = mp.Get(service, user)
	assertError(t, err, mp.mockError)

	err = mp.Delete(service, user)
	assertError(t, err, mp.mockError)
}

// TestMockDeleteAll tests deleting all secrets for a given service.
func TestMockDeleteAll(t *testing.T) {
	mp := mockProvider{}

	// Set up multiple secrets for the same service
	err := mp.Set(service, user, password)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	err = mp.Set(service, user+"2", password+"2")
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	// Delete all secrets for the service
	err = mp.DeleteAll(service)
	if err != nil {
		t.Errorf("Should not fail, got: %s", err)
	}

	// Verify that all secrets for the service are deleted
	_, err = mp.Get(service, user)
	assertError(t, err, ErrNotFound)

	_, err = mp.Get(service, user+"2")
	assertError(t, err, ErrNotFound)

	// Verify that DeleteAll on an empty service doesn't cause an error
	err = mp.DeleteAll(service)
	if err != nil {
		t.Errorf("Should not fail on empty service, got: %s", err)
	}
}

func assertError(t *testing.T, err error, expected error) {
	if err != expected {
		t.Errorf("Expected error %s, got %s", expected, err)
	}
}
```
