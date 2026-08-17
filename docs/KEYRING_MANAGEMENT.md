# Gestión de secretos (keyring)

`tinywasm/keyring` proporciona almacenamiento seguro de credenciales sobre cuatro backends:
Windows Credential Manager, macOS Keychain, Linux Secret Service y Navegador (WebCrypto + IndexedDB).

## API

### Keyring genérico (por servicio con inyección de proveedor)

```go
import (
    "github.com/tinywasm/keyring"
    "github.com/tinywasm/keyring/linux"
)

kr, err := keyring.NewKeyring("my-app", linux.New())
if err != nil {
    // keyring no disponible
}
kr.SetLog(log.Printf) // opcional

kr.Set("github_token", "ghp_...")   // guardar
token, err := kr.Get("github_token") // leer
kr.Delete("github_token")            // borrar
```

### Selección automática (shortcut `auto`)

```go
import keyring "github.com/tinywasm/keyring/auto"

kr := keyring.OpenKeyring("my-app")
```

### KeyManager (servicio `updater-cicd`)

```go
import (
    "github.com/tinywasm/keyring"
    "github.com/tinywasm/keyring/auto"
)

km := keyring.New(auto.Provider())
km.Setup("hmac-secret-value", "github-pat-value")
```

## Backend intercambiable (tests)

Las operaciones pasan por la interfaz `Provider`. Los tests inyectan un proveedor en memoria (`tests.NewMemProvider()`) a través del constructor de `Keyring`, permitiendo ejecución paralela segura.

## Requisitos del sistema

- **Linux**: Secret Service sobre `tinywasm/dbus` (`gnome-keyring` auto-instalable con `Ensure`).
- **Windows**: Credential Manager vía `advapi32.dll`.
- **macOS**: Keychain vía `/usr/bin/security`.
- **Navegador**: WebCrypto API e IndexedDB vía `syscall/js`.
