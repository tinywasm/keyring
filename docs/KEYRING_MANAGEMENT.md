# Gestión de secretos (keyring)

`tinywasm/keyring` proporciona almacenamiento seguro de credenciales sobre el
keyring nativo del sistema operativo (Windows Credential Manager, macOS
Keychain, Linux Secret Service), con una capa de instalación automática en
Linux cuando falta `gnome-keyring`.

Internamente usa [zalando/go-keyring](https://github.com/zalando/go-keyring).

## API

### Keyring genérico (por servicio)

La API recomendada. Cada `Keyring` está acotado a un *service name*: la misma
clave en servicios distintos nunca colisiona, así un proceso puede gestionar
secretos de varias aplicaciones.

```go
import "github.com/tinywasm/keyring"

// Verifica el backend y auto-instala dependencias en Linux si faltan.
kr, err := keyring.NewKeyring("my-app")
if err != nil {
    // keyring no disponible (o instalación fallida)
}
kr.SetLog(log.Printf) // opcional

kr.Set("github_token", "ghp_...")   // guardar
token, err := kr.Get("github_token") // leer
kr.Delete("github_token")            // borrar
```

> Es el tipo que implementa `SecretStore` de `github.com/tinywasm/git`:
> inyecta `keyring.NewKeyring("devflow")` para conservar los tokens ya
> almacenados, o un store en memoria en tests/CI.

### KeyManager (servicio `updater-cicd`)

Maneja los secretos clásicos del servicio `updater-cicd`:

```go
const (
    ServiceName   = "updater-cicd"
    HMACSecretKey = "hmac-secret"
    GitHubPATKey  = "github-pat"
)
```

```go
km := keyring.New()

// Setup inicial (primera ejecución)
err := km.Setup("hmac-secret-value", "github-pat-value")

// Lectura
hmacSecret, err := km.GetHMACSecret()
githubPAT, err := km.GetGitHubPAT()

// Rotación
err = km.RotateHMACSecret("new-hmac")
err = km.RotateGitHubPAT("new-pat")

// Utilidades
configured := km.IsConfigured()
err = km.DeleteAll() // reset completo
```

## Backend intercambiable (tests)

Las operaciones pasan por la interfaz `Provider`. Por defecto el backend es el
keyring del sistema; los tests lo sustituyen por un proveedor en memoria y lo
restauran después:

```go
real := keyring.GetProvider()
keyring.SetProvider(myMemProvider)
defer keyring.SetProvider(real)
```

La verificación de `NewKeyring` y todas las operaciones funcionan contra el
proveedor inyectado — ningún test toca credenciales reales.

## Diagramas

- [Arquitectura](keyring-architecture.mermaid)
- [Secuencia de Operaciones](keyring-sequence.mermaid)

## Requisitos del sistema

- **Linux**: `gnome-keyring` + `libsecret` (auto-instalables vía apt/dnf/pacman
  con `NewKeyring`, y `gnome-keyring-daemon` se arranca si no corre).
- **Windows**: Credential Manager; el usuario que ejecuta la app debe ser el
  que almacenó los secretos (o tener permisos adecuados).
- **macOS**: Keychain.