← [Stage 3 — macOS](PLAN_STAGE_3_DARWIN.md) | Stage 4 of 6 | Next → [Stage 5 — Browser](PLAN_STAGE_5_BROWSER.md)

# Stage 4 — Linux backend on the Secret Service, over `tinywasm/dbus`

## Prerequisite

`github.com/tinywasm/dbus` must be released before this stage starts. Its plan
is at `https://github.com/tinywasm/dbus/blob/main/docs/PLAN.md`. If the module
does not exist yet, **stop and report** — do not vendor a D-Bus implementation
into this repository.

```bash
go get github.com/tinywasm/dbus@latest
```

This is the only `require` line `keyring/go.mod` ends up with.

## This stage is a port

The source is `keyring_unix.go` plus `secret_service/secret_service.go`,
appended verbatim in appendices A and B. **Reproduce their logic**; the only
substitution is `github.com/godbus/dbus/v5` → `github.com/tinywasm/dbus`, whose
API was designed against exactly these call sites.

Two things in the original look like accidents and are not — keep both:

- the collection fallback (`/collection/login`, then the alias) — distributions
  differ, and each path alone fails somewhere;
- the prompt handling — a locked keyring returns a prompt path instead of
  completing, and ignoring it hangs the caller.

## Ground rules for this folder

`keyring/linux/` needs **no build tag**: nothing in it is platform-locked at the
compiler level, and a browser build simply never imports it. The stdlib (`os`,
`os/exec`, `strings`) is correct here and must not be replaced. See
[PLAN.md](PLAN.md) §2.

## No compatibility layer

This is a breaking change ([PLAN.md](PLAN.md) §4). The attribute map below is
what the port produces because it is what the original produces — **not** a
contract to preserve. Write no fallback that searches for records in any other
shape.

```go
attributes := map[string]string{
	"username": user,
	"service":  service,
}
```

The item label `Password for '<user>' on '<service>'` is cosmetic; it is what a
user sees in Seahorse, so keep it readable.

## 1. The seven D-Bus calls this backend makes

All on destination `org.freedesktop.secrets`.

| # | Object | Method | In | Out |
|---|---|---|---|---|
| 1 | `/org/freedesktop/secrets` | `org.freedesktop.Secret.Service.OpenSession` | `"plain"`, `Variant("")` | `Variant`, `ObjectPath` (session) |
| 2 | `/org/freedesktop/secrets` | `org.freedesktop.DBus.Properties.Get` | `"org.freedesktop.Secret.Service"`, `"Collections"` | `Variant([]ObjectPath)` |
| 3 | `/org/freedesktop/secrets` | `org.freedesktop.Secret.Service.Unlock` | `[]ObjectPath{collection}` | `[]ObjectPath`, `ObjectPath` (prompt) |
| 4 | collection | `org.freedesktop.Secret.Collection.CreateItem` | `map[string]Variant` (props), `Secret`, `true` | `ObjectPath` (item), `ObjectPath` (prompt) |
| 5 | collection | `org.freedesktop.Secret.Collection.SearchItems` | `map[string]string` | `[]ObjectPath` |
| 6 | item | `org.freedesktop.Secret.Item.GetSecret` | `ObjectPath` (session) | `Secret` |
| 7 | item | `org.freedesktop.Secret.Item.Delete` | — | `ObjectPath` (prompt) |

Plus `org.freedesktop.Secret.Session.Close` on the session when done — always
via `defer`, or the daemon accumulates sessions for the life of the process.

### The `Secret` struct

```go
// Secret is the org.freedesktop.Secret.Item secret structure. Its D-Bus
// signature is (oayays) and the field order is part of the wire format.
type Secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}
```

`ContentType` is `"text/plain; charset=utf8"` and `Parameters` is an empty (not
nil) slice — the `plain` session negotiated in call 1 does no encryption.

### Choosing the collection

Try `/org/freedesktop/secrets/collection/login` first, and verify it exists by
reading the `Collections` property (call 2) and looking for that exact path. If
it is absent, fall back to the alias
`/org/freedesktop/secrets/aliases/default`. Reproduce this fallback exactly:
distributions differ, and the alias alone fails on some while the literal path
fails on others.

### Prompts

Calls 3, 4 and 7 may return a prompt path instead of completing. `/` means "no
prompt". Anything else must be driven:

1. `AddMatch` for `type='signal',interface='org.freedesktop.Secret.Prompt',path='<prompt>'`
2. register a signal channel
3. call `org.freedesktop.Secret.Prompt.Prompt("")`
4. wait for `Completed(dismissed bool, result Variant)`
5. `RemoveMatch`

**Register the match and the channel before calling `Prompt`**, or the signal
can arrive first and be lost — leaving the caller blocked until the D-Bus
timeout. `dismissed == true` means the user cancelled: return `ErrUnavailable`,
not a hang and not a silent success.

`Unlock` additionally merges the paths from the prompt result into the unlocked
set and verifies the collection is among them; keep that check.

## 2. Provider implementation

```go
package linux

func New() *Provider
func (p *Provider) Set(service, user, password string) error
func (p *Provider) Get(service, user string) (string, error)
func (p *Provider) Delete(service, user string) error
func (p *Provider) DeleteAll(service string) error
func (p *Provider) Ensure(log func(...any)) error   // the Ensurer from stage 1
```

Each operation opens a connection, does its work and closes — matching the
current behaviour. Do **not** cache a long-lived connection in this stage: a
`Keyring` may sit idle for hours, and a stale socket surfaces as a confusing
error at an unrelated call site. Note the possibility in `docs/` and leave it.

`Get` order of operations: search → if no results, `ErrNotFound`; open a
session; unlock the item itself (an individual item can be locked even inside
an unlocked collection); `GetSecret`; return `string(secret.Value)`.

`DeleteAll` returns `ErrNotFound` when `service == ""` — the guard against
deleting every secret on the machine. Searching by `{"service": service}` alone
(no `username`) and deleting each hit is correct; an empty result set is `nil`,
not an error.

## 3. The installer moves here

`tryInstallKeyring` and `startKeyringService`, deleted from the root package in
stage 1, land in `linux/ensure.go` as the body of `Ensure`. Preserve the
behaviour exactly:

```go
var packageManagers = []struct {
	cmd  string
	args []string
}{
	{"apt", []string{"sudo", "apt", "install", "-y", "gnome-keyring", "libsecret-1-0"}},
	{"dnf", []string{"sudo", "dnf", "install", "-y", "gnome-keyring", "libsecret"}},
	{"pacman", []string{"sudo", "pacman", "-S", "--noconfirm", "gnome-keyring", "libsecret"}},
}
```

`Ensure`:

1. `log("⚙️  Installing keyring dependencies...")`
2. for each entry whose `cmd` is found by `exec.LookPath`, log
   `"   Installing via <cmd>..."` and run it; the first success wins
3. if none succeeded, return the verbatim manual-install message:

```
could not install keyring. Install manually:
  Debian/Ubuntu: sudo apt install gnome-keyring libsecret-1-0
  Fedora: sudo dnf install gnome-keyring libsecret
  Arch: sudo pacman -S gnome-keyring libsecret
```

4. start the daemon: if `gnome-keyring-daemon` is on `PATH`, run
   `gnome-keyring-daemon --start --components=secrets`, parse each `KEY=VALUE`
   line of its stdout and `os.Setenv` them — this is how `DBUS_SESSION_BUS_ADDRESS`
   and `GNOME_KEYRING_CONTROL` reach the current process. Dropping this makes
   the install succeed and the very next call fail.
5. `log("✅ Keyring installed successfully")` is emitted by the **root
   package** after its re-probe succeeds, not here. `Ensure` returns nil.

Do not run the package managers from any test.

## 4. Tests

The Secret Service is a live desktop daemon; CI has no session bus. Structure
the tests so the parts that can be verified, are:

0. **Run the conformance suite from stage 1 §8b against this backend**, twice:

   ```go
   // against the fake bus below — always runs
   func TestLinuxConformanceFake(t *testing.T) {
       RunConformance(t, providerOn(fakeBus(t)), true)  // true: no size limit on Linux
   }

   // against the real daemon — skipped when there is no session bus
   func TestLinuxConformanceReal(t *testing.T) {
       if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
           t.Skip("no session bus: run on a desktop to exercise the real Secret Service")
       }
       RunConformance(t, linux.New(), true)
   }
   ```

   The second one is why the suite was ported: on the maintainer's machine it
   exercises the real daemon, which is the only place some of these bugs appear.

1. **A fake Secret Service over the `tinywasm/dbus` fake bus.** The dbus module
   ships `tests/fakebus_test.go`; build the equivalent here: a goroutine that
   speaks the seven calls of §1 against an in-memory map, with
   `DBUS_SESSION_BUS_ADDRESS` pointing at a socket in `t.TempDir()`. Assert:
   - `Set` then `Get` returns the value
   - `Get` for an absent key returns `ErrNotFound`
   - `Delete` removes it; a second `Delete` returns `ErrNotFound`
   - `DeleteAll("")` returns `ErrNotFound` **without contacting the bus**
   - a prompt path other than `/` triggers `Prompt` and completes on the signal
   - `dismissed == true` yields `ErrUnavailable`
   - a search for a service returns only that service's items, never another's
2. **`Ensure` with an injected runner.** `Ensure` must not shell out directly:
   give the provider an unexported `run func(name string, args ...string) error`
   and `lookPath func(string) (string, error)`, defaulting to the real ones.
   Tests inject fakes and assert the manager order (apt → dnf → pacman), that
   the first success stops the loop, and that the verbatim message comes back
   when all fail. Without this seam the installer is untestable.
3. **Skip, do not fake, the real-daemon test.** If
   `DBUS_SESSION_BUS_ADDRESS` is unset, `t.Skip` with a clear reason.

## 5. Acceptance checklist

```bash
grep -rn "godbus\|zalando" .              # → empty
grep -n "tinywasm/dbus" go.mod            # → the only require
GOOS=linux go build ./... && GOOS=linux go vet ./...
GOOS=js GOARCH=wasm go build ./...        # linux/ must not leak into WASM
gotest
```

At the end of this stage the native platforms are complete and the repository
has **one** dependency, inside the ecosystem.

---

## Appendix A — source to port: `keyring_unix.go`

From `github.com/zalando/go-keyring@v0.2.6`, MIT. Replace the `godbus`
import with `github.com/tinywasm/dbus`; the call sites map one to one.

```go
//go:build (dragonfly && cgo) || (freebsd && cgo) || linux || netbsd || openbsd

package keyring

import (
	"fmt"

	dbus "github.com/godbus/dbus/v5"
	ss "github.com/zalando/go-keyring/secret_service"
)

type secretServiceProvider struct{}

// Set stores user and pass in the keyring under the defined service
// name.
func (s secretServiceProvider) Set(service, user, pass string) error {
	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}

	// open a session
	session, err := svc.OpenSession()
	if err != nil {
		return err
	}
	defer svc.Close(session)

	attributes := map[string]string{
		"username": user,
		"service":  service,
	}

	secret := ss.NewSecret(session.Path(), pass)

	collection := svc.GetLoginCollection()

	err = svc.Unlock(collection.Path())
	if err != nil {
		return err
	}

	err = svc.CreateItem(collection,
		fmt.Sprintf("Password for '%s' on '%s'", user, service),
		attributes, secret)
	if err != nil {
		return err
	}

	return nil
}

// findItem looksup an item by service and user.
func (s secretServiceProvider) findItem(svc *ss.SecretService, service, user string) (dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"username": user,
		"service":  service,
	}

	err := svc.Unlock(collection.Path())
	if err != nil {
		return "", err
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return "", err
	}

	if len(results) == 0 {
		return "", ErrNotFound
	}

	return results[0], nil
}

// findServiceItems looksup all items by service.
func (s secretServiceProvider) findServiceItems(svc *ss.SecretService, service string) ([]dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"service": service,
	}

	err := svc.Unlock(collection.Path())
	if err != nil {
		return []dbus.ObjectPath{}, err
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return []dbus.ObjectPath{}, err
	}

	if len(results) == 0 {
		return []dbus.ObjectPath{}, ErrNotFound
	}

	return results, nil
}

// Get gets a secret from the keyring given a service name and a user.
func (s secretServiceProvider) Get(service, user string) (string, error) {
	svc, err := ss.NewSecretService()
	if err != nil {
		return "", err
	}

	item, err := s.findItem(svc, service, user)
	if err != nil {
		return "", err
	}

	// open a session
	session, err := svc.OpenSession()
	if err != nil {
		return "", err
	}
	defer svc.Close(session)

	// unlock if invdividual item is locked
	err = svc.Unlock(item)
	if err != nil {
		return "", err
	}

	secret, err := svc.GetSecret(item, session.Path())
	if err != nil {
		return "", err
	}

	return string(secret.Value), nil
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (s secretServiceProvider) Delete(service, user string) error {
	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}

	item, err := s.findItem(svc, service, user)
	if err != nil {
		return err
	}

	return svc.Delete(item)
}

// DeleteAll deletes all secrets for a given service
func (s secretServiceProvider) DeleteAll(service string) error {
	// if service is empty, do nothing otherwise it might accidentally delete all secrets
	if service == "" {
		return ErrNotFound
	}

	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}
	// find all items for the service
	items, err := s.findServiceItems(svc, service)
	if err != nil {
		if err == ErrNotFound {
			return nil
		}
		return err
	}
	for _, item := range items {
		err = svc.Delete(item)
		if err != nil {
			return err
		}
	}
	return nil
}

func init() {
	provider = secretServiceProvider{}
}
```

## Appendix B — source to port: `secret_service/secret_service.go`

Same origin and licence. This becomes the internals of `keyring/linux/`;
it does NOT need to be a separate package.

```go
package ss

import (
	"fmt"

	"errors"

	dbus "github.com/godbus/dbus/v5"
)

const (
	serviceName          = "org.freedesktop.secrets"
	servicePath          = "/org/freedesktop/secrets"
	serviceInterface     = "org.freedesktop.Secret.Service"
	collectionInterface  = "org.freedesktop.Secret.Collection"
	collectionsInterface = "org.freedesktop.Secret.Service.Collections"
	itemInterface        = "org.freedesktop.Secret.Item"
	sessionInterface     = "org.freedesktop.Secret.Session"
	promptInterface      = "org.freedesktop.Secret.Prompt"

	loginCollectionAlias = "/org/freedesktop/secrets/aliases/default"
	collectionBasePath   = "/org/freedesktop/secrets/collection/"
)

// Secret defines a org.freedesk.Secret.Item secret struct.
type Secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string `dbus:"content_type"`
}

// NewSecret initializes a new Secret.
func NewSecret(session dbus.ObjectPath, secret string) Secret {
	return Secret{
		Session:     session,
		Parameters:  []byte{},
		Value:       []byte(secret),
		ContentType: "text/plain; charset=utf8",
	}
}

// SecretService is an interface for the Secret Service dbus API.
type SecretService struct {
	*dbus.Conn
	object dbus.BusObject
}

// NewSecretService inializes a new SecretService object.
func NewSecretService() (*SecretService, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, err
	}

	return &SecretService{
		conn,
		conn.Object(serviceName, servicePath),
	}, nil
}

// OpenSession opens a secret service session.
func (s *SecretService) OpenSession() (dbus.BusObject, error) {
	var disregard dbus.Variant
	var sessionPath dbus.ObjectPath
	err := s.object.Call(serviceInterface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&disregard, &sessionPath)
	if err != nil {
		return nil, err
	}

	return s.Object(serviceName, sessionPath), nil
}

// CheckCollectionPath accepts dbus path and returns nil if the path is found
// in the collection interface (and can be used).
func (s *SecretService) CheckCollectionPath(path dbus.ObjectPath) error {
	obj := s.Conn.Object(serviceName, servicePath)
	val, err := obj.GetProperty(collectionsInterface)
	if err != nil {
		return err
	}
	paths := val.Value().([]dbus.ObjectPath)
	for _, p := range paths {
		if p == path {
			return nil
		}
	}
	return errors.New("path not found")
}

// GetCollection returns a collection from a name.
func (s *SecretService) GetCollection(name string) dbus.BusObject {
	return s.Object(serviceName, dbus.ObjectPath(collectionBasePath+name))
}

// GetLoginCollection decides and returns the dbus collection to be used for login.
func (s *SecretService) GetLoginCollection() dbus.BusObject {
	path := dbus.ObjectPath(collectionBasePath + "login")
	if err := s.CheckCollectionPath(path); err != nil {
		path = dbus.ObjectPath(loginCollectionAlias)
	}
	return s.Object(serviceName, path)
}

// Unlock unlocks a collection.
func (s *SecretService) Unlock(collection dbus.ObjectPath) error {
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	err := s.object.Call(serviceInterface+".Unlock", 0, []dbus.ObjectPath{collection}).Store(&unlocked, &prompt)
	if err != nil {
		return err
	}

	_, v, err := s.handlePrompt(prompt)
	if err != nil {
		return err
	}

	collections := v.Value()
	switch c := collections.(type) {
	case []dbus.ObjectPath:
		unlocked = append(unlocked, c...)
	}

	if len(unlocked) != 1 || (collection != loginCollectionAlias && unlocked[0] != collection) {
		return fmt.Errorf("failed to unlock correct collection '%v'", collection)
	}

	return nil
}

// Close closes a secret service dbus session.
func (s *SecretService) Close(session dbus.BusObject) error {
	return session.Call(sessionInterface+".Close", 0).Err
}

// CreateCollection with the supplied label.
func (s *SecretService) CreateCollection(label string) (dbus.BusObject, error) {
	properties := map[string]dbus.Variant{
		collectionInterface + ".Label": dbus.MakeVariant(label),
	}
	var collection, prompt dbus.ObjectPath
	err := s.object.Call(serviceInterface+".CreateCollection", 0, properties, "").
		Store(&collection, &prompt)
	if err != nil {
		return nil, err
	}

	_, v, err := s.handlePrompt(prompt)
	if err != nil {
		return nil, err
	}

	if v.String() != "" {
		collection = dbus.ObjectPath(v.String())
	}

	return s.Object(serviceName, collection), nil
}

// CreateItem creates an item in a collection, with label, attributes and a
// related secret.
func (s *SecretService) CreateItem(collection dbus.BusObject, label string, attributes map[string]string, secret Secret) error {
	properties := map[string]dbus.Variant{
		itemInterface + ".Label":      dbus.MakeVariant(label),
		itemInterface + ".Attributes": dbus.MakeVariant(attributes),
	}

	var item, prompt dbus.ObjectPath
	err := collection.Call(collectionInterface+".CreateItem", 0,
		properties, secret, true).Store(&item, &prompt)
	if err != nil {
		return err
	}

	_, _, err = s.handlePrompt(prompt)
	if err != nil {
		return err
	}

	return nil
}

// handlePrompt checks if a prompt should be handles and handles it by
// triggering the prompt and waiting for the Secret service daemon to display
// the prompt to the user.
func (s *SecretService) handlePrompt(prompt dbus.ObjectPath) (bool, dbus.Variant, error) {
	if prompt != dbus.ObjectPath("/") {
		err := s.AddMatchSignal(dbus.WithMatchObjectPath(prompt),
			dbus.WithMatchInterface(promptInterface),
		)
		if err != nil {
			return false, dbus.MakeVariant(""), err
		}

		defer func(s *SecretService, options ...dbus.MatchOption) {
			_ = s.RemoveMatchSignal(options...)
		}(s, dbus.WithMatchObjectPath(prompt), dbus.WithMatchInterface(promptInterface))

		promptSignal := make(chan *dbus.Signal, 1)
		s.Signal(promptSignal)

		err = s.Object(serviceName, prompt).Call(promptInterface+".Prompt", 0, "").Err
		if err != nil {
			return false, dbus.MakeVariant(""), err
		}

		signal := <-promptSignal
		switch signal.Name {
		case promptInterface + ".Completed":
			dismissed := signal.Body[0].(bool)
			result := signal.Body[1].(dbus.Variant)
			return dismissed, result, nil
		}

	}

	return false, dbus.MakeVariant(""), nil
}

// SearchItems returns a list of items matching the search object.
func (s *SecretService) SearchItems(collection dbus.BusObject, search interface{}) ([]dbus.ObjectPath, error) {
	var results []dbus.ObjectPath
	err := collection.Call(collectionInterface+".SearchItems", 0, search).Store(&results)
	if err != nil {
		return nil, err
	}

	return results, nil
}

// GetSecret gets secret from an item in a given session.
func (s *SecretService) GetSecret(itemPath dbus.ObjectPath, session dbus.ObjectPath) (*Secret, error) {
	var secret Secret
	err := s.Object(serviceName, itemPath).Call(itemInterface+".GetSecret", 0, session).Store(&secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

// Delete deletes an item from the collection.
func (s *SecretService) Delete(itemPath dbus.ObjectPath) error {
	var prompt dbus.ObjectPath
	err := s.Object(serviceName, itemPath).Call(itemInterface+".Delete", 0).Store(&prompt)
	if err != nil {
		return err
	}

	_, _, err = s.handlePrompt(prompt)
	if err != nil {
		return err
	}

	return nil
}
```
