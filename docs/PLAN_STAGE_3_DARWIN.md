← [Stage 2 — Windows](PLAN_STAGE_2_WINDOWS.md) | Stage 3 of 6 | Next → [Stage 4 — Linux](PLAN_STAGE_4_LINUX.md)

# Stage 3 — macOS backend on `/usr/bin/security`

## Goal

**Port** `keyring_darwin.go` (appendix A) and drop
`al.essio.dev/pkg/shellescape`, the last dependency that exists purely to quote
three strings. Roughly 150 lines.

⚠️ **This file is not zalando's own code.** It carries a *"Copyright 2013 Google
Inc. — Apache License, Version 2.0"* header. Copy that header verbatim to the
top of the ported file and list it in the repository's `NOTICE`. Deleting it is
a licence violation, not a tidy-up.

## Ground rules for this folder

`keyring/darwin/` is **native-only** — `//go:build darwin` on every file. The
stdlib (`os/exec`, `strings`, `encoding/base64`, `io`) is correct here and must
not be replaced; this code cannot reach a WASM binary. See [PLAN.md](PLAN.md) §2.

## Drop the legacy decoding path

The original recognises **two** value prefixes on read:

| Prefix | Origin |
|---|---|
| `go-keyring-base64:` | what `Set` writes |
| `go-keyring-encoded:` | hex, written by versions that predate the base64 switch |

**Port only the first.** The hex branch exists solely to read records written
years ago by another library — exactly the dead legacy this plan refuses to
carry ([PLAN.md](PLAN.md) §4). Delete it, along with the `encoding/hex` import.

Use this repository's own prefix, so the format is ours and no reader is
tempted to reintroduce compatibility later:

```go
const valuePrefix = "tw-keyring-b64:"
```

Acceptance: `grep -rn "go-keyring-encoded\|go-keyring-base64\|encoding/hex" .`
→ empty.

## 1. Why the value is encoded at all

`security find-generic-password -w` hex-encodes its output when the value
contains newlines or non-ASCII bytes, so a raw multi-line secret comes back as
garbage. Encoding on write sidesteps the ambiguity entirely. This is not
optional cleverness — remove it and multi-line PATs break.

## 2. Why the password goes through stdin

`Set` does **not** pass the password as a command-line argument. It starts
`security -i` (interactive mode) and writes the `add-generic-password` command
to its stdin, because arguments are visible to any user via `ps`. Keep that
shape; it is a security property, not a style choice.

Because the command is a line of text parsed by `security`, the three
interpolated values must be quoted — which is the only thing `shellescape`
was doing.

## 3. `quote` — replaces the dependency

```go
// quote renders s as a single shell-safe token for security(1)'s interactive
// parser. Unquoted when it contains only characters the parser cannot
// misinterpret; otherwise single-quoted, with embedded single quotes closed,
// escaped and reopened ('\'' → '"'"').
func quote(s string) string {
	if s == "" {
		return "''"
	}
	if !needsQuoting(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// needsQuoting reports whether s contains anything outside the safe set
// [A-Za-z0-9_@%+=:,./-].
func needsQuoting(s string) bool { /* ... */ }
```

Table-test it — this is pure logic and runs on any platform:

| input | output |
|---|---|
| `abc` | `abc` |
| `` (empty) | `''` |
| `a b` | `'a b'` |
| `it's` | `'it'"'"'s'` |
| `$(rm -rf /)` | `'$(rm -rf /)'` |
| `a/b-c.d_e` | `a/b-c.d_e` |

The `it's` and `$(...)` rows are the ones that matter: the first proves the
quote-closing dance is right, the second proves command substitution cannot
escape the quoting.

## 4. Provider implementation

Constants first — no literals in logic:

```go
const (
	execPathKeychain = "/usr/bin/security"
	valuePrefix      = "tw-keyring-b64:"
	notFoundMarker   = "could not be found"
	maxCommandBytes  = 4096
)
```

**`Get(service, user)`**
`security find-generic-password -s <service> -wa <user>`, `CombinedOutput`.
If the output contains `notFoundMarker` → `ErrNotFound`. Trim whitespace, then
base64-decode the remainder when the value carries `valuePrefix`, and otherwise
return it literally.

**`Set(service, user, password)`**
Encode `valuePrefix + base64.StdEncoding.EncodeToString(...)`. Start
`security -i`, get its stdin pipe, `Start`, then write:

```
add-generic-password -U -s <quoted service> -a <quoted user> -w <quoted encoded>\n
```

If that line exceeds `maxCommandBytes` return `ErrTooBig` **before** writing.
Close stdin, `Wait`. The `-U` flag updates an existing item instead of failing —
keep it.

**`Delete(service, user)`**
`security delete-generic-password -s <service> -a <user>`; the `notFoundMarker`
in the output means `ErrNotFound`.

**`DeleteAll(service)`**
Return `ErrNotFound` when `service == ""`. Otherwise loop
`security delete-generic-password -s <service>` until the output contains
`notFoundMarker`, then return nil. **Bound this loop** — the original has no
cap and spins forever if `security` ever returns a different failure. Cap it at
1000 iterations and return `ErrUnavailable` if it is hit; a real Keychain never
holds that many items for one service.

Error sentinels come straight from the root package — `keyring.ErrNotFound`,
`keyring.Wrap(...)`. There is no import cycle and no translation layer.

## 5. Testing on a non-macOS machine

0. **Wire this backend into the conformance suite** from stage 1 §8b, in a file
   tagged `//go:build darwin` under `tests/`:

   ```go
   //go:build darwin

   func TestDarwinConformance(t *testing.T) {
       RunConformance(t, darwin.New(), false)   // false: security(1) caps the command line
   }
   ```

   `GetMultiLine` and `GetUmlaut` in that suite are **specifically** the cases
   this backend's base64 encoding exists for — they came from macOS bugs. This
   is the stage where they earn their keep.
1. **`GOOS=darwin go build ./...` and `go vet` are the gate.**
2. **Put the platform-independent logic where `gotest` can reach it.**
   `quote`, `needsQuoting`, the prefix encode/decode, and the command-length
   check go in `darwin/encoding.go` **with no build tag** and no `os/exec`
   import. Test on Linux:
   - `quote` table from §3.
   - Round-trip: `encodeValue("línea1\nlínea2")` then `decodeValue` returns the
     original.
   - `decodeValue("plain")` returns `"plain"` unchanged.
   - A command built from a 4100-byte password is rejected with `ErrTooBig`.
3. **`docs/DARWIN_VERIFICATION.md`** records the manual steps: store a secret,
   confirm it appears in Keychain Access under the service name, confirm a
   multi-line value round-trips, and confirm the password never appears in
   `ps` output while `Set` runs.

## 6. Acceptance checklist

```bash
grep -rn "shellescape\|al.essio.dev" .    # → empty
GOOS=darwin go build ./... && GOOS=darwin go vet ./...
GOOS=js GOARCH=wasm go build ./...        # darwin/ must not leak into WASM
gotest
```

---

## Appendix A — source to port: `keyring_darwin.go`

From `github.com/zalando/go-keyring@v0.2.6`. **Apache-2.0, Copyright 2013
Google Inc.** — keep the header verbatim in the ported file. Replace
`shellescape.Quote` with the local `quote` from §3, and DELETE the
`go-keyring-encoded:` hex branch and the `encoding/hex` import (§"Drop the
legacy decoding path").

```go
// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keyring

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"al.essio.dev/pkg/shellescape"
)

const (
	execPathKeychain = "/usr/bin/security"

	// encodingPrefix is a well-known prefix added to strings encoded by Set.
	encodingPrefix       = "go-keyring-encoded:"
	base64EncodingPrefix = "go-keyring-base64:"
)

type macOSXKeychain struct{}

// func (*MacOSXKeychain) IsAvailable() bool {
// 	return exec.Command(execPathKeychain).Run() != exec.ErrNotFound
// }

// Get password from macos keyring given service and user name.
func (k macOSXKeychain) Get(service, username string) (string, error) {
	out, err := exec.Command(
		execPathKeychain,
		"find-generic-password",
		"-s", service,
		"-wa", username).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "could not be found") {
			err = ErrNotFound
		}
		return "", err
	}

	trimStr := strings.TrimSpace(string(out[:]))
	// if the string has the well-known prefix, assume it's encoded
	if strings.HasPrefix(trimStr, encodingPrefix) {
		dec, err := hex.DecodeString(trimStr[len(encodingPrefix):])
		return string(dec), err
	} else if strings.HasPrefix(trimStr, base64EncodingPrefix) {
		dec, err := base64.StdEncoding.DecodeString(trimStr[len(base64EncodingPrefix):])
		return string(dec), err
	}

	return trimStr, nil
}

// Set stores a secret in the macos keyring given a service name and a user.
func (k macOSXKeychain) Set(service, username, password string) error {
	// if the added secret has multiple lines or some non ascii,
	// osx will hex encode it on return. To avoid getting garbage, we
	// encode all passwords
	password = base64EncodingPrefix + base64.StdEncoding.EncodeToString([]byte(password))

	cmd := exec.Command(execPathKeychain, "-i")
	stdIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err = cmd.Start(); err != nil {
		return err
	}

	command := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", shellescape.Quote(service), shellescape.Quote(username), shellescape.Quote(password))
	if len(command) > 4096 {
		return ErrSetDataTooBig
	}

	if _, err := io.WriteString(stdIn, command); err != nil {
		return err
	}

	if err = stdIn.Close(); err != nil {
		return err
	}

	err = cmd.Wait()
	return err
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (k macOSXKeychain) Delete(service, username string) error {
	out, err := exec.Command(
		execPathKeychain,
		"delete-generic-password",
		"-s", service,
		"-a", username).CombinedOutput()
	if strings.Contains(string(out), "could not be found") {
		err = ErrNotFound
	}
	return err
}

// DeleteAll deletes all secrets for a given service
func (k macOSXKeychain) DeleteAll(service string) error {
	// if service is empty, do nothing otherwise it might accidentally delete all secrets
	if service == "" {
		return ErrNotFound
	}
	// Delete each secret in a while loop until there is no more left
	// under the service
	for {
		out, err := exec.Command(
			execPathKeychain,
			"delete-generic-password",
			"-s", service).CombinedOutput()
		if strings.Contains(string(out), "could not be found") {
			return nil
		} else if err != nil {
			return err
		}
	}

}

func init() {
	provider = macOSXKeychain{}
}
```
