package keyring

// Provider abstracts the OS keyring backend (Secret Service, Keychain,
// Credential Manager).
type Provider interface {
	// Set stores password for user under service.
	Set(service, user, password string) error
	// Get returns the password stored for user under service.
	Get(service, user string) (string, error)
	// Delete removes the password stored for user under service.
	Delete(service, user string) error
	// DeleteAll removes every entry under service.
	DeleteAll(service string) error
}

// Fallback answers every call with ErrUnsupported. It is what auto.Provider()
// returns on platforms with no credential store.
type Fallback struct{}

func (Fallback) Set(service, user, password string) error { return ErrUnsupported }
func (Fallback) Get(service, user string) (string, error) { return "", ErrUnsupported }
func (Fallback) Delete(service, user string) error        { return ErrUnsupported }
func (Fallback) DeleteAll(service string) error           { return ErrUnsupported }

// Ensurer is implemented by backends that can repair their own prerequisites
// (install packages, start a daemon). NewKeyring calls it when the initial
// probe fails. Backends that cannot self-repair simply do not implement it.
type Ensurer interface {
	Ensure(log func(...any)) error
}
