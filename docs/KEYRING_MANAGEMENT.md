# GESTIÓN DE SECRETOS (KEYRING)

La librería `tinywasm/keyring` proporciona una interfaz unificada y segura para gestionar secretos del sistema, utilizando el almacenamiento seguro nativo del sistema operativo (Windows Credential Manager en Windows).

## Implementación

Esta librería utiliza internamente [zalando/go-keyring](https://github.com/zalando/go-keyring).

### Diagramas

- [Arquitectura](keyring-architecture.mermaid)
- [Secuencia de Operaciones](keyring-sequence.mermaid)

### Constantes Definidas

```go
const (
    ServiceName   = "updater-cicd"
    HMACSecretKey = "hmac-secret"
    GitHubPATKey  = "github-pat"
)
```

### API

#### Inicialización

```go
import "github.com/tinywasm/keyring"

km := keyring.New()
```

#### Setup Inicial

Configura los secretos por primera vez.

```go
err := km.Setup("hmac-secret-value", "github-pat-value")
if err != nil {
    // Manejo de error
}
```

#### Obtención de Secretos

Recupera los valores almacenados de forma segura.

```go
// Obtener HMAC Secret
hmacSecret, err := km.GetHMACSecret()

// Obtener GitHub PAT
githubPAT, err := km.GetGitHubPAT()
```

#### Rotación de Secretos

Actualiza los valores existentes.

```go
// Rotar HMAC
err := km.RotateHMACSecret("new-hmac-secret")

// Rotar PAT
err := km.RotateGitHubPAT("new-github-pat")
```

#### Utilidades

```go
// Verificar si ya está configurado (existen ambos secretos)
configured := km.IsConfigured()

// Eliminar todos los secretos (Factory Reset)
err := km.DeleteAll()
```

## Requisitos del Sistema

- **Windows**: Requiere acceso al Credential Manager. El usuario que ejecuta la aplicación debe ser el mismo que almacenó los secretos (o tener permisos adecuados).
