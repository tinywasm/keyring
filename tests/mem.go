package tests

import "github.com/tinywasm/keyring"

// MemProvider is an in-memory Provider for tests. Err, when non-nil, is
// returned by every method — use it to drive failure paths.
type MemProvider struct {
	store map[string]map[string]string
	Err   error
}

// NewMemProvider creates an initialized in-memory provider.
func NewMemProvider() *MemProvider {
	return &MemProvider{
		store: make(map[string]map[string]string),
	}
}

// Set stores user and pass in the keyring under the defined service name.
func (m *MemProvider) Set(service, user, pass string) error {
	if m.Err != nil {
		return m.Err
	}
	if m.store == nil {
		m.store = make(map[string]map[string]string)
	}
	if m.store[service] == nil {
		m.store[service] = make(map[string]string)
	}
	m.store[service][user] = pass
	return nil
}

// Get gets a secret from the keyring given a service name and a user.
func (m *MemProvider) Get(service, user string) (string, error) {
	if m.Err != nil {
		return "", m.Err
	}
	if b, ok := m.store[service]; ok {
		if v, ok := b[user]; ok {
			return v, nil
		}
	}
	return "", keyring.ErrNotFound
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (m *MemProvider) Delete(service, user string) error {
	if m.Err != nil {
		return m.Err
	}
	if m.store != nil {
		if _, ok := m.store[service]; ok {
			if _, ok := m.store[service][user]; ok {
				delete(m.store[service], user)
				return nil
			}
		}
	}
	return keyring.ErrNotFound
}

// DeleteAll deletes all secrets for a given service.
func (m *MemProvider) DeleteAll(service string) error {
	if m.Err != nil {
		return m.Err
	}
	if m.store != nil {
		delete(m.store, service)
	}
	return nil
}
