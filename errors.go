package keyring

// Error is the error type of this package. It is a comparable string so
// callers can use errors.Is / == without this package importing "errors".
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrNotFound is returned when the key has no value in this service.
	ErrNotFound Error = "keyring: secret not found"
	// ErrUnsupported is returned by the fallback backend on platforms with no
	// credential store.
	ErrUnsupported Error = "keyring: no credential store on this platform"
	// ErrTooBig is returned when the value exceeds the backend's limit.
	ErrTooBig Error = "keyring: value too large for the platform credential store"
	// ErrUnavailable is returned when a backend exists but cannot be reached
	// (no D-Bus session, locked keychain, storage blocked by the browser).
	ErrUnavailable Error = "keyring: credential store unavailable"
	// ErrNoProvider is returned when a Keyring is built with a nil provider.
	ErrNoProvider Error = "keyring: no provider injected"
)

// Wrap returns an error whose message is prefix + ": " + err.Error(), and whose
// Unwrap returns err so errors.Is still matches the sentinel. Exported because
// the backend packages use it.
func Wrap(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return &wrapped{prefix: prefix, err: err}
}

type wrapped struct {
	prefix string
	err    error
}

func (w *wrapped) Error() string { return w.prefix + ": " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }
