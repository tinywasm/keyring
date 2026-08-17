# keyring
<img src="docs/img/badges.svg">

Secure credential storage for Go on **four** environments — Linux (Secret
Service), macOS (Keychain), Windows (Credential Manager) and the **browser**
(WebCrypto + IndexedDB) — with no third-party dependencies.

The core decides nothing: it holds no backend, no build tags and no package
state. **The caller injects the backend it wants**, so a browser build never
links a line of `os/exec`, and a CLI never links `syscall/js`.

```go
import (
    "github.com/tinywasm/keyring"
    "github.com/tinywasm/keyring/linux"
)

kr, err := keyring.NewKeyring("my-app", linux.New())
kr.SetLog(log.Printf)
kr.Set("github_token", pat)
tok, err := kr.Get("github_token")
kr.Delete("github_token")
```

### Don't care which backend? Use `auto`

A multiplatform CLI just wants "whatever this machine has". `keyring/auto`
picks it, and is the only package in the repository that chooses:

```go
import keyring "github.com/tinywasm/keyring/auto"

kr, err := keyring.NewKeyring("my-app") // Secret Service, Keychain,
                                        // Credential Manager or browser
```

A browser application does **not** import `auto` — it knows where it runs:

```go
import "github.com/tinywasm/keyring/browser"

kr := keyring.OpenKeyring("my-app", browser.New())
```

### The browser backend

Secrets are AES-GCM encrypted in IndexedDB under a data key that is itself
wrapped by one or more key-encryption keys:

| KEK | Unlock | Status |
|---|---|---|
| `device` | none — a non-extractable `CryptoKey` in IndexedDB | always present |
| `passkey` | WebAuthn PRF + biometric | opt-in, `EnrollPasskey` |
| `recovery` | passphrase | designed, not built |

Because the key is a non-extractable `CryptoKey`, script running in the origin
can ask it to decrypt but **cannot read the key material out of the page**.
That is unreachable from a Go implementation, where any key is bytes in wasm
linear memory that JS can read — which is why this backend calls WebCrypto
instead of encrypting in Go. Full threat model, including what it does *not*
protect against: [docs/BROWSER_SECURITY.md](docs/BROWSER_SECURITY.md).

`Set`/`Get`/`Delete` keep their synchronous signatures by blocking on
`github.com/tinywasm/await`, so **they must be called from a goroutine**, never
from the wasm main function or directly inside a JS event callback.

### No keyring on the machine?

`NewKeyring` probes the backend on startup, and asks it to repair itself when
it knows how. The Linux backend implements that: it installs `gnome-keyring` +
`libsecret` with the distro package manager and starts `gnome-keyring-daemon`.
`OpenKeyring` never probes — use it when the store is only needed
conditionally, or in CI where `GH_TOKEN` may stand in.

### Testing

There is no package-level provider to swap, so tests inject an in-memory one
through the constructor and can run in parallel:

```go
kr := keyring.OpenKeyring("test", tests.NewMemProvider())
```

`tests/conformance.go` holds the contract every backend must satisfy —
multi-line values, non-ASCII, hex-looking passwords, the empty-service guard on
`DeleteAll` — and each backend runs it.

## Documentation

- [Keyring Management](docs/KEYRING_MANAGEMENT.md)
- [Architecture](docs/keyring-architecture.mermaid)
- [Sequence](docs/keyring-sequence.mermaid)
