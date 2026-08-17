package keyring

// Keyring provides scoped credential storage through an injected backend.
// The service name is a namespace: the same key under different services never
// collides, so one process can hold secrets for several apps.
type Keyring struct {
	service  string
	provider Provider
	log      func(...any)
}

// NewKeyring creates a Keyring scoped to service over provider p, and verifies
// the backend actually works — asking it to repair itself when it implements
// Ensurer.
//
// Callers that do not care which backend they get can use
// github.com/tinywasm/keyring/auto, which picks one for the target platform.
func NewKeyring(service string, p Provider) (*Keyring, error) {
	k := &Keyring{
		service:  service,
		provider: p,
		log:      func(...any) {},
	}
	if p == nil {
		return nil, ErrNoProvider
	}
	if err := k.ensureAvailable(); err != nil {
		return nil, err
	}
	return k, nil
}

// OpenKeyring creates a Keyring without probing the backend: nothing is touched
// until the first Get/Set/Delete. Use it when the store is only needed
// conditionally (session recovery) or in flows that may legitimately run
// without one (CI with GH_TOKEN).
func OpenKeyring(service string, p Provider) *Keyring {
	return &Keyring{
		service:  service,
		provider: p,
		log:      func(...any) {},
	}
}

// SetLog sets the logging function.
func (k *Keyring) SetLog(fn func(...any)) {
	if fn != nil {
		k.log = fn
	}
}

// Set stores value under key in this service's namespace.
func (k *Keyring) Set(key, value string) error {
	if k.provider == nil {
		return ErrNoProvider
	}
	return k.provider.Set(k.service, key, value)
}

// Get returns the value stored under key in this service's namespace.
func (k *Keyring) Get(key string) (string, error) {
	if k.provider == nil {
		return "", ErrNoProvider
	}
	return k.provider.Get(k.service, key)
}

// Delete removes key from this service's namespace.
func (k *Keyring) Delete(key string) error {
	if k.provider == nil {
		return ErrNoProvider
	}
	return k.provider.Delete(k.service, key)
}

// ensureAvailable probes the backend with a throwaway write and, if that fails,
// asks the backend to repair itself when it knows how.
func (k *Keyring) ensureAvailable() error {
	const probeKey = "keyring_test_probe"

	if err := k.provider.Set(k.service, probeKey, "test"); err == nil {
		k.provider.Delete(k.service, probeKey)
		return nil
	}

	e, ok := k.provider.(Ensurer)
	if !ok {
		return ErrUnavailable
	}
	if err := e.Ensure(k.log); err != nil {
		return err
	}

	if err := k.provider.Set(k.service, probeKey, "test"); err != nil {
		return Wrap("keyring: still unavailable after repair", err)
	}
	k.provider.Delete(k.service, probeKey)
	return nil
}
