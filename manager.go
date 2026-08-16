package keyring

import (
	"fmt"
)

const (
	ServiceName   = "updater-cicd"
	HMACSecretKey = "hmac-secret"
	GitHubPATKey  = "github-pat"
)

// KeyManager manages the service-exposed secrets (HMAC secret, GitHub PAT)
// of ServiceName on top of a generic Keyring. Same API as before; now
// backed by the shared Keyring type.
type KeyManager struct {
	kr *Keyring
}

// New creates a KeyManager over the ServiceName service.
func New() *KeyManager {
	return &KeyManager{kr: &Keyring{service: ServiceName, log: func(...any) {}}}
}

// SetLog sets the logging function.
func (m *KeyManager) SetLog(fn func(...any)) {
	m.kr.SetLog(fn)
}

// Setup realiza el setup inicial - solo primera ejecución
func (m *KeyManager) Setup(hmacSecret, githubPAT string) error {
	if err := m.kr.Set(HMACSecretKey, hmacSecret); err != nil {
		return fmt.Errorf("failed to store HMAC secret: %w", err)
	}

	if err := m.kr.Set(GitHubPATKey, githubPAT); err != nil {
		return fmt.Errorf("failed to store GitHub PAT: %w", err)
	}

	return nil
}

// GetHMACSecret obtiene el HMAC secret
func (m *KeyManager) GetHMACSecret() (string, error) {
	secret, err := m.kr.Get(HMACSecretKey)
	if err != nil {
		return "", fmt.Errorf("HMAC secret not found in keyring: %w", err)
	}
	return secret, nil
}

// GetGitHubPAT obtiene el GitHub PAT
func (m *KeyManager) GetGitHubPAT() (string, error) {
	pat, err := m.kr.Get(GitHubPATKey)
	if err != nil {
		return "", fmt.Errorf("GitHub PAT not found in keyring: %w", err)
	}
	return pat, nil
}

// RotateHMACSecret rota el HMAC secret
func (m *KeyManager) RotateHMACSecret(newSecret string) error {
	return m.kr.Set(HMACSecretKey, newSecret)
}

// RotateGitHubPAT rota el GitHub PAT
func (m *KeyManager) RotateGitHubPAT(newPAT string) error {
	return m.kr.Set(GitHubPATKey, newPAT)
}

// IsConfigured verifica si están configurados
func (m *KeyManager) IsConfigured() bool {
	_, err1 := m.kr.Get(HMACSecretKey)
	_, err2 := m.kr.Get(GitHubPATKey)
	return err1 == nil && err2 == nil
}

// DeleteAll elimina todos los secretos (reset)
func (m *KeyManager) DeleteAll() error {
	// Intentamos eliminar ambos, si uno falla devolvemos el error pero intentamos el otro
	var err1, err2 error

	if err := m.kr.Delete(HMACSecretKey); err != nil {
		err1 = err
	}
	if err := m.kr.Delete(GitHubPATKey); err != nil {
		err2 = err
	}

	if err1 != nil {
		return err1
	}
	return err2
}