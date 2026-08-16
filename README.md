# keyring
<img src="docs/img/badges.svg">

Secure credential storage for Go, backed by the OS keyring
(Windows Credential Manager, macOS Keychain, Linux Secret Service).

Two APIs on the same backend:

- **`Keyring`** — generic, service-scoped key/value store. Ideal as the
  `SecretStore` of `github.com/tinywasm/git` and for CLI auth flows.
- **`KeyManager`** — the classic manager for the `updater-cicd` service
  secrets (HMAC secret + GitHub PAT) with Setup/Rotate/Reset semantics.

```go
import "github.com/tinywasm/keyring"

// Service-scoped store: same key names never collide across services.
kr, err := keyring.NewKeyring("my-app")
if err != nil { /* OS keyring missing; it auto-installs on Linux */ }
kr.SetLog(log.Printf)
kr.Set("github_token", pat)
tok, err := kr.Get("github_token")
kr.Delete("github_token")

// Classic manager (updater-cicd service).
km := keyring.New()
km.Setup(hmacSecret, pat)
```

### No keyring on the machine?

`NewKeyring` verifies the backend on startup and, on Linux, tries to install
`gnome-keyring` + `libsecret` with the distro package manager, then starts
`gnome-keyring-daemon`. Tests never touch the OS keyring: they swap the backend
with `keyring.SetProvider` and restore it with `keyring.GetProvider`.

## Documentation

- [Keyring Management](docs/KEYRING_MANAGEMENT.md)
- [Architecture](docs/keyring-architecture.mermaid)
- [Sequence](docs/keyring-sequence.mermaid)