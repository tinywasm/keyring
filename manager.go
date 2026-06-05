package keyring

import (
	"fmt"

	"github.com/zalando/go-keyring"
)

const (
	ServiceName   = "updater-cicd"
	HMACSecretKey = "hmac-secret"
	GitHubPATKey  = "github-pat"
)

type KeyManager struct{}

func New() *KeyManager {
	return &KeyManager{}
}

// Setup inicial - solo primera ejecución
func (m *KeyManager) Setup(hmacSecret, githubPAT string) error {
	if err := keyring.Set(ServiceName, HMACSecretKey, hmacSecret); err != nil {
		return fmt.Errorf("failed to store HMAC secret: %w", err)
	}

	if err := keyring.Set(ServiceName, GitHubPATKey, githubPAT); err != nil {
		return fmt.Errorf("failed to store GitHub PAT: %w", err)
	}

	return nil
}

// Obtener HMAC secret
func (m *KeyManager) GetHMACSecret() (string, error) {
	secret, err := keyring.Get(ServiceName, HMACSecretKey)
	if err != nil {
		return "", fmt.Errorf("HMAC secret not found in keyring: %w", err)
	}
	return secret, nil
}

// Obtener GitHub PAT
func (m *KeyManager) GetGitHubPAT() (string, error) {
	pat, err := keyring.Get(ServiceName, GitHubPATKey)
	if err != nil {
		return "", fmt.Errorf("GitHub PAT not found in keyring: %w", err)
	}
	return pat, nil
}

// Rotar HMAC secret
func (m *KeyManager) RotateHMACSecret(newSecret string) error {
	return keyring.Set(ServiceName, HMACSecretKey, newSecret)
}

// Rotar GitHub PAT
func (m *KeyManager) RotateGitHubPAT(newPAT string) error {
	return keyring.Set(ServiceName, GitHubPATKey, newPAT)
}

// Verificar si están configurados
func (m *KeyManager) IsConfigured() bool {
	_, err1 := keyring.Get(ServiceName, HMACSecretKey)
	_, err2 := keyring.Get(ServiceName, GitHubPATKey)
	return err1 == nil && err2 == nil
}

// Eliminar todos los secretos (reset)
func (m *KeyManager) DeleteAll() error {
	// Intentamos eliminar ambos, si uno falla devolvemos el error pero intentamos el otro
	var err1, err2 error
	
	if err := keyring.Delete(ServiceName, HMACSecretKey); err != nil {
		err1 = err
	}
	if err := keyring.Delete(ServiceName, GitHubPATKey); err != nil {
		err2 = err
	}
	
	if err1 != nil {
		return err1
	}
	return err2
}
