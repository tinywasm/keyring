// Portions Copyright (c) 2014 Zalando SE — MIT
//
// Ported from github.com/zalando/go-keyring's secret_service package, with
// github.com/godbus/dbus/v5 replaced by github.com/tinywasm/dbus. The call
// sequence, the attribute map and the prompt handling are reproduced as-is:
// each of them is a behaviour real Secret Service daemons depend on.

package linux

import (
	"time"

	"github.com/tinywasm/dbus"
	"github.com/tinywasm/keyring"
)

// ObjectPath is the D-Bus object path type, aliased so this package's callers
// need not import tinywasm/dbus directly.
type ObjectPath = dbus.ObjectPath

// Conn is a session bus connection.
type Conn = dbus.Conn

const (
	serviceName         = "org.freedesktop.secrets"
	servicePath         = ObjectPath("/org/freedesktop/secrets")
	serviceInterface    = "org.freedesktop.Secret.Service"
	collectionInterface = "org.freedesktop.Secret.Collection"
	itemInterface       = "org.freedesktop.Secret.Item"
	sessionInterface    = "org.freedesktop.Secret.Session"
	promptInterface     = "org.freedesktop.Secret.Prompt"

	loginCollectionAlias = ObjectPath("/org/freedesktop/secrets/aliases/default")
	loginCollectionPath  = ObjectPath("/org/freedesktop/secrets/collection/login")

	noPrompt = ObjectPath("/")

	// promptTimeout bounds the wait for a Prompt.Completed signal. The user may
	// simply walk away from an unlock dialog; without this the call would block
	// the caller forever.
	promptTimeout = 2 * time.Minute
)

// busObject pairs a remote object with its path. dbus.Object does not expose
// its own path, and the Secret Service call sequence needs it (Unlock takes the
// collection path, GetSecret takes the session path).
type busObject struct {
	obj  *dbus.Object
	path ObjectPath
}

// Path returns the object's D-Bus path.
func (b *busObject) Path() ObjectPath { return b.path }

// Secret is the org.freedesktop.Secret.Item secret structure. Its D-Bus
// signature is (oayays) and the field order is part of the wire format — do not
// reorder.
type Secret struct {
	Session     ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// NewSecret initializes a Secret for a plain (unencrypted) session.
func NewSecret(session ObjectPath, secret string) Secret {
	return Secret{
		Session:     session,
		Parameters:  []byte{},
		Value:       []byte(secret),
		ContentType: "text/plain; charset=utf8",
	}
}

// SecretService is a client of the org.freedesktop.secrets D-Bus API.
type SecretService struct {
	*Conn
	object *busObject
}

// SessionBus dials the session bus.
func SessionBus() (*Conn, error) {
	return dbus.SessionBus()
}

// NewSecretService opens its own connection to the session bus.
func NewSecretService() (*SecretService, error) {
	conn, err := SessionBus()
	if err != nil {
		return nil, err
	}
	return NewSecretServiceOnConn(conn), nil
}

// NewSecretServiceOnConn reuses an existing connection. Tests inject a
// connection to a fake bus through it.
func NewSecretServiceOnConn(conn *Conn) *SecretService {
	return &SecretService{
		Conn: conn,
		object: &busObject{
			obj:  conn.Object(serviceName, servicePath),
			path: servicePath,
		},
	}
}

// CloseConn closes the underlying bus connection.
func (svc *SecretService) CloseConn() {
	if svc.Conn != nil {
		_ = svc.Conn.Close()
	}
}

// OpenSession opens a plain (unencrypted) secret service session.
func (svc *SecretService) OpenSession() (*busObject, error) {
	var disregard dbus.Variant
	var sessionPath ObjectPath

	err := svc.object.obj.
		Call(serviceInterface+".OpenSession", "plain", dbus.MakeVariant("")).
		Store(&disregard, &sessionPath)
	if err != nil {
		return nil, err
	}

	return &busObject{
		obj:  svc.Conn.Object(serviceName, sessionPath),
		path: sessionPath,
	}, nil
}

// Close closes a session opened with OpenSession. Sessions accumulate in the
// daemon for the life of the process if this is skipped.
func (svc *SecretService) Close(session *busObject) error {
	return session.obj.Call(sessionInterface + ".Close").Err
}

// checkCollectionPath reports whether path appears in the service's Collections
// property.
func (svc *SecretService) checkCollectionPath(path ObjectPath) error {
	val, err := svc.object.obj.GetProperty(serviceInterface, "Collections")
	if err != nil {
		return err
	}
	paths, ok := val.Value().([]ObjectPath)
	if !ok {
		return keyring.ErrUnavailable
	}
	for _, p := range paths {
		if p == path {
			return nil
		}
	}
	return keyring.ErrNotFound
}

// GetLoginCollection returns the collection secrets are stored in.
//
// It prefers the literal /collection/login path and falls back to the default
// alias. Both forms are needed: distributions differ, and each one alone fails
// on some of them.
func (svc *SecretService) GetLoginCollection() *busObject {
	path := loginCollectionPath
	if err := svc.checkCollectionPath(path); err != nil {
		path = loginCollectionAlias
	}
	return &busObject{
		obj:  svc.Conn.Object(serviceName, path),
		path: path,
	}
}

// Unlock unlocks a collection or an individual item, driving the prompt the
// daemon returns when the keyring is locked.
func (svc *SecretService) Unlock(path ObjectPath) error {
	var unlocked []ObjectPath
	var prompt ObjectPath

	err := svc.object.obj.
		Call(serviceInterface+".Unlock", []ObjectPath{path}).
		Store(&unlocked, &prompt)
	if err != nil {
		return err
	}

	_, v, err := svc.handlePrompt(prompt)
	if err != nil {
		return err
	}
	if paths, ok := v.Value().([]ObjectPath); ok {
		unlocked = append(unlocked, paths...)
	}

	if len(unlocked) != 1 || (path != loginCollectionAlias && unlocked[0] != path) {
		return keyring.ErrUnavailable
	}
	return nil
}

// CreateItem stores a secret in a collection under the given attributes.
func (svc *SecretService) CreateItem(collection *busObject, label string, attributes map[string]string, secret Secret) error {
	properties := map[string]dbus.Variant{
		itemInterface + ".Label":      dbus.MakeVariant(label),
		itemInterface + ".Attributes": dbus.MakeVariant(attributes),
	}

	var item, prompt ObjectPath
	err := collection.obj.
		Call(collectionInterface+".CreateItem", properties, secret, true).
		Store(&item, &prompt)
	if err != nil {
		return err
	}

	_, _, err = svc.handlePrompt(prompt)
	return err
}

// SearchItems returns the item paths in collection matching every attribute in
// search.
func (svc *SecretService) SearchItems(collection *busObject, search map[string]string) ([]ObjectPath, error) {
	var results []ObjectPath
	err := collection.obj.
		Call(collectionInterface+".SearchItems", search).
		Store(&results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// GetSecret reads an item's secret within an open session.
func (svc *SecretService) GetSecret(itemPath, session ObjectPath) (*Secret, error) {
	var secret Secret
	err := svc.Conn.Object(serviceName, itemPath).
		Call(itemInterface+".GetSecret", session).
		Store(&secret)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// Delete removes an item from its collection.
func (svc *SecretService) Delete(itemPath ObjectPath) error {
	var prompt ObjectPath
	err := svc.Conn.Object(serviceName, itemPath).
		Call(itemInterface + ".Delete").
		Store(&prompt)
	if err != nil {
		return err
	}

	_, _, err = svc.handlePrompt(prompt)
	return err
}

// handlePrompt drives a prompt the daemon asked for, waiting for the user to
// answer the unlock dialog.
//
// The match rule and the signal channel are registered BEFORE calling Prompt:
// the Completed signal can arrive before the Prompt call returns, and a signal
// that lands with no channel registered is dropped, leaving the caller blocked.
func (svc *SecretService) handlePrompt(prompt ObjectPath) (bool, dbus.Variant, error) {
	if prompt == noPrompt || prompt == "" {
		return false, dbus.MakeVariant(""), nil
	}

	rule := "type='signal',interface='" + promptInterface +
		"',path='" + string(prompt) + "'"
	if err := svc.Conn.AddMatch(rule); err != nil {
		return false, dbus.MakeVariant(""), err
	}
	defer func() { _ = svc.Conn.RemoveMatch(rule) }()

	ch := make(chan *dbus.Signal, 8)
	svc.Conn.Signals(ch)

	if err := svc.Conn.Object(serviceName, prompt).
		Call(promptInterface + ".Prompt").Err; err != nil {
		return false, dbus.MakeVariant(""), err
	}

	timeout := time.NewTimer(promptTimeout)
	defer timeout.Stop()

	for {
		select {
		case sig := <-ch:
			if sig == nil || sig.Path != prompt || sig.Name != promptInterface+".Completed" {
				continue
			}
			var dismissed bool
			var result dbus.Variant
			if len(sig.Body) > 0 {
				dismissed, _ = sig.Body[0].(bool)
			}
			if len(sig.Body) > 1 {
				result, _ = sig.Body[1].(dbus.Variant)
			}
			if dismissed {
				// The user cancelled the unlock dialog. That is a refusal, not
				// a transient failure: report it instead of hanging or
				// pretending the secret is simply absent.
				return true, result, keyring.ErrUnavailable
			}
			return false, result, nil
		case <-timeout.C:
			return false, dbus.MakeVariant(""), keyring.ErrUnavailable
		}
	}
}
