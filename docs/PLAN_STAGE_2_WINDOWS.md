← [Stage 1 — Core](PLAN_STAGE_1_CORE.md) | Stage 2 of 6 | Next → [Stage 3 — macOS](PLAN_STAGE_3_DARWIN.md)

# Stage 2 — Windows backend on `advapi32.dll`

## Goal

**Port** `keyring_windows.go` (appendix A), replacing
`github.com/danieljoos/wincred` (and its `golang.org/x/sys` dependency) with
direct calls to the Windows Credential Manager through the **stdlib** `syscall`
package. Roughly 250 lines, no third-party code.

This is a port: the control flow, the guards and the error handling of the
original are already correct. Reproduce them. The only thing being replaced is
how the four `Cred*` functions are reached.

## Ground rules for this folder

`keyring/windows/` is **native-only** — `//go:build windows` on every file,
because `syscall.NewLazyDLL` exists on no other platform. The stdlib (`syscall`,
`unsafe`, `strings`, `unicode/utf16`) is correct here and must not be replaced
with `tinywasm/*` packages: this code cannot reach a WASM binary. See
[PLAN.md](PLAN.md) §2.

## No compatibility layer

This is a breaking change ([PLAN.md](PLAN.md) §4). Write nothing to keep old
records readable.

The record shape below matches what `wincred` wrote — target name
`<service>:<username>`, type `CRED_TYPE_GENERIC`, raw password bytes in the
blob, `Persist` = `CRED_PERSIST_LOCAL_MACHINE` — **because that is the obvious
way to store a generic credential**, not because compatibility is a goal. Do not
add a fallback that reads any other shape.

## 1. Win32 bindings

```go
//go:build windows

package windows

import "syscall"

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCredReadW      = advapi32.NewProc("CredReadW")
	procCredWriteW     = advapi32.NewProc("CredWriteW")
	procCredDeleteW    = advapi32.NewProc("CredDeleteW")
	procCredEnumerateW = advapi32.NewProc("CredEnumerateW")
	procCredFree       = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric          = 1
	credPersistLocalMachine  = 2
	errorNotFound            = syscall.Errno(1168) // ERROR_NOT_FOUND
	maxBlobBytes             = 2560                // documented Credential Manager limit
	maxTargetBytes           = 512
)
```

Every `Proc.Call` returns `(r1, r2 uintptr, lastErr error)`. These four
functions return a **BOOL**: success is `r1 != 0`. **`lastErr` is only
meaningful when `r1 == 0`** — reading it on success yields a stale
"The operation completed successfully" error. Getting this backwards is the most
common way to break `syscall.NewLazyDLL` code.

## 2. The `CREDENTIAL` struct — field order is load-bearing

```go
type filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// credential mirrors the Win32 CREDENTIALW structure. The field order and
// types must match the C layout exactly; Go's natural alignment on amd64 and
// 386 already inserts the padding the C compiler does. DO NOT reorder, group,
// or "tidy" these fields.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}
```

Memory returned by `CredReadW` and `CredEnumerateW` is **allocated by Windows**
and must be released with `CredFree` — `defer procCredFree.Call(ptr)` on every
success path. Copy the blob into a Go slice **before** freeing:

```go
blob := make([]byte, cred.CredentialBlobSize)
copy(blob, unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize))
```

Never let a `*byte` into Windows-owned memory outlive the `CredFree`.

## 3. Provider implementation

`New() *Provider` returns the backend. The four methods:

**`Get(service, user)`** — `CredReadW(target, credTypeGeneric, 0, &ptr)`.
On failure, if `lastErr == errorNotFound` return `("", ErrNotFound)`, otherwise
wrap it. On success copy the blob, `CredFree`, return `string(blob)`.

**`Set(service, user, password)`** — validate first, in this order:

| Check | Error |
|---|---|
| `len(password) > maxBlobBytes` | `ErrTooBig` |
| `len(service) >= maxTargetBytes` | `ErrTooBig` |

then build a `credential` with `Type: credTypeGeneric`, `Persist:
credPersistLocalMachine`, `TargetName` and `UserName` from
`syscall.UTF16PtrFromString`, and `CredentialBlob` pointing at the password
bytes, and call `CredWriteW(&cred, 0)`.

**`Delete(service, user)`** — `CredDeleteW(target, credTypeGeneric, 0)`;
`errorNotFound` → `ErrNotFound`.

**`DeleteAll(service)`** — return `ErrNotFound` immediately when `service == ""`
(a guard that prevents wiping every credential on the machine — keep it).
Otherwise `CredEnumerateW(nil, 0, &count, &creds)`, walk the returned array of
`*credential` with `unsafe.Slice`, and delete every entry whose `TargetName`
starts with `<service> + ":"`. `CredFree` the array once. An entry that
disappears between enumeration and deletion (`errorNotFound`) is skipped, not
an error.

Errors are the root package's sentinels, used **directly**:

```go
import "github.com/tinywasm/keyring"

// ...
return "", keyring.ErrNotFound
return keyring.Wrap("keyring/windows: CredWriteW", err)
```

There is no import cycle and no translation layer: `keyring` imports nothing, so
every backend imports `keyring` freely. (An earlier draft of this plan, written
around `init()` registration, called for duplicated sentinels and a mapping
adapter. Injection deletes both — do not reintroduce them.)

## 4. Testing on a non-Windows machine

Windows cannot be exercised in this environment. Be honest about that rather
than faking it:

0. **Wire this backend into the conformance suite** built in stage 1 §8b, in a
   file tagged `//go:build windows` under `tests/`:

   ```go
   //go:build windows

   func TestWindowsConformance(t *testing.T) {
       RunConformance(t, windows.New(), false)   // false: this backend HAS size limits
   }
   ```

   It will not run here, but it is the definition of done for this stage and it
   runs the moment someone builds on Windows. Write it now, not later.
1. **Compile check is mandatory and is the gate:** `GOOS=windows go build ./...`
   and `GOOS=windows go vet ./...` must both pass.
2. **Unit-test what is platform-independent** by extracting it: `credName`
   (`<service>:<username>`), the size validations, and the `DeleteAll` prefix
   filter belong in `windows/credname.go` with **no build tag** and no `syscall`
   import, so `gotest` covers them on Linux. Table-test:

   | service | user | expected target |
   |---|---|---|
   | `devflow` | `github-pat` | `devflow:github-pat` |
   | `devflow` | `` | `devflow:` |
   | `` | `x` | `:x` |

3. **Record manual verification steps** in `docs/WINDOWS_VERIFICATION.md`:
   set a secret, read it back, confirm with `cmdkey /list` that the target name
   is `devflow:github-pat`, delete it, and confirm it is gone. Do not claim this
   ran if it did not.

## 5. Acceptance checklist

```bash
grep -rn "wincred\|golang.org/x/sys" .    # → empty
GOOS=windows go build ./... && GOOS=windows go vet ./...
GOOS=js GOARCH=wasm go build ./...        # windows/ must not leak into WASM
gotest                                    # credname tests pass on Linux
```

---

## Appendix A — source to port: `keyring_windows.go`

From `github.com/zalando/go-keyring@v0.2.6`, MIT. Reproduce this logic;
replace only `wincred` with the `advapi32.dll` bindings from §1–§2.

```go
package keyring

import (
	"strings"
	"syscall"

	"github.com/danieljoos/wincred"
)

type windowsKeychain struct{}

// Get gets a secret from the keyring given a service name and a user.
func (k windowsKeychain) Get(service, username string) (string, error) {
	cred, err := wincred.GetGenericCredential(k.credName(service, username))
	if err != nil {
		if err == syscall.ERROR_NOT_FOUND {
			return "", ErrNotFound
		}
		return "", err
	}

	return string(cred.CredentialBlob), nil
}

// Set stores stores user and pass in the keyring under the defined service
// name.
func (k windowsKeychain) Set(service, username, password string) error {
	// password may not exceed 2560 bytes (https://github.com/jaraco/keyring/issues/540#issuecomment-968329967)
	if len(password) > 2560 {
		return ErrSetDataTooBig
	}

	// service may not exceed 512 bytes (might need more testing)
	if len(service) >= 512 {
		return ErrSetDataTooBig
	}

	// service may not exceed 32k but problems occur before that
	// so we limit it to 30k
	if len(service) > 1024*30 {
		return ErrSetDataTooBig
	}

	cred := wincred.NewGenericCredential(k.credName(service, username))
	cred.UserName = username
	cred.CredentialBlob = []byte(password)
	return cred.Write()
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (k windowsKeychain) Delete(service, username string) error {
	cred, err := wincred.GetGenericCredential(k.credName(service, username))
	if err != nil {
		if err == syscall.ERROR_NOT_FOUND {
			return ErrNotFound
		}
		return err
	}

	return cred.Delete()
}

func (k windowsKeychain) DeleteAll(service string) error {
	// if service is empty, do nothing otherwise it might accidentally delete all secrets
	if service == "" {
		return ErrNotFound
	}

	creds, err := wincred.List()
	if err != nil {
		return err
	}

	prefix := k.credName(service, "")
	deletedCount := 0

	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, prefix) {
			genericCred, err := wincred.GetGenericCredential(cred.TargetName)
			if err != nil {
				if err != syscall.ERROR_NOT_FOUND {
					return err
				}
			} else {
				err := genericCred.Delete()
				if err != nil {
					return err
				}
				deletedCount++
			}
		}
	}
	return nil
}

// credName combines service and username to a single string.
func (k windowsKeychain) credName(service, username string) string {
	return service + ":" + username
}

func init() {
	provider = windowsKeychain{}
}
```
