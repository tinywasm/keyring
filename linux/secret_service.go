package linux

import (
	"fmt"

	dbus "github.com/tinywasm/dbus"
)

type ObjectPath string
type Variant struct{ val any }

func MakeVariant(v any) Variant { return Variant{val: v} }
func (v Variant) Value() any    { return v.val }

type Signal struct {
	Name string
	Body []any
}

type Call struct {
	Err error
}

func (c *Call) Store(out ...any) error {
	return c.Err
}

type BusObject interface {
	Call(method string, flags int, args ...any) *Call
	GetProperty(prop string) (Variant, error)
	Path() ObjectPath
}

type Conn struct {
	db *dbus.Dbus
}

func SessionBus() (*Conn, error) {
	return &Conn{db: dbus.New()}, nil
}

func (c *Conn) Close() error { return nil }

func (c *Conn) Object(dest string, path ObjectPath) BusObject {
	return &fakeBusObject{dest: dest, path: path}
}

func (c *Conn) AddMatchSignal(options ...any) error    { return nil }
func (c *Conn) RemoveMatchSignal(options ...any) error { return nil }
func (c *Conn) Signal(ch chan<- *Signal)               {}

type fakeBusObject struct {
	dest string
	path ObjectPath
}

func (f *fakeBusObject) Path() ObjectPath { return f.path }

func (f *fakeBusObject) Call(method string, flags int, args ...any) *Call {
	return &Call{Err: fmt.Errorf("dbus call %s not implemented on fake", method)}
}

func (f *fakeBusObject) GetProperty(prop string) (Variant, error) {
	return Variant{}, fmt.Errorf("property %s not implemented on fake", prop)
}

const (
	serviceName          = "org.freedesktop.secrets"
	servicePath          = ObjectPath("/org/freedesktop/secrets")
	serviceInterface     = "org.freedesktop.Secret.Service"
	collectionInterface  = "org.freedesktop.Secret.Collection"
	collectionsInterface = "org.freedesktop.Secret.Service.Collections"
	itemInterface        = "org.freedesktop.Secret.Item"
	sessionInterface     = "org.freedesktop.Secret.Session"
	promptInterface      = "org.freedesktop.Secret.Prompt"

	loginCollectionAlias = ObjectPath("/org/freedesktop/secrets/aliases/default")
	collectionBasePath   = ObjectPath("/org/freedesktop/secrets/collection/")
)

// Secret defines a org.freedesktop.Secret.Item secret struct.
type Secret struct {
	Session     ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string `dbus:"content_type"`
}

// NewSecret initializes a new Secret.
func NewSecret(session ObjectPath, secret string) Secret {
	return Secret{
		Session:     session,
		Parameters:  []byte{},
		Value:       []byte(secret),
		ContentType: "text/plain; charset=utf8",
	}
}

type SecretService struct {
	*Conn
	object BusObject
}

func NewSecretService() (*SecretService, error) {
	conn, err := SessionBus()
	if err != nil {
		return nil, err
	}

	return &SecretService{
		conn,
		conn.Object(serviceName, servicePath),
	}, nil
}

func NewSecretServiceOnConn(conn *Conn) *SecretService {
	return &SecretService{
		Conn:   conn,
		object: conn.Object(serviceName, servicePath),
	}
}

func (s *SecretService) OpenSession() (BusObject, error) {
	var disregard Variant
	var sessionPath ObjectPath
	err := s.object.Call(serviceInterface+".OpenSession", 0, "plain", MakeVariant("")).Store(&disregard, &sessionPath)
	if err != nil {
		return nil, err
	}

	return s.Object(serviceName, sessionPath), nil
}

func (s *SecretService) CheckCollectionPath(path ObjectPath) error {
	obj := s.Conn.Object(serviceName, servicePath)
	val, err := obj.GetProperty(collectionsInterface)
	if err != nil {
		return err
	}
	paths, ok := val.Value().([]ObjectPath)
	if !ok {
		return fmt.Errorf("invalid collections property type")
	}
	for _, p := range paths {
		if p == path {
			return nil
		}
	}
	return fmt.Errorf("path not found")
}

func (s *SecretService) GetLoginCollection() BusObject {
	path := ObjectPath(string(collectionBasePath) + "login")
	if err := s.CheckCollectionPath(path); err != nil {
		path = loginCollectionAlias
	}
	return s.Object(serviceName, path)
}

func (s *SecretService) Unlock(collection ObjectPath) error {
	var unlocked []ObjectPath
	var prompt ObjectPath
	err := s.object.Call(serviceInterface+".Unlock", 0, []ObjectPath{collection}).Store(&unlocked, &prompt)
	if err != nil {
		return err
	}

	dismissed, v, err := s.handlePrompt(prompt)
	if err != nil {
		return err
	}
	if dismissed {
		return fmt.Errorf("prompt dismissed")
	}

	collections := v.Value()
	switch c := collections.(type) {
	case []ObjectPath:
		unlocked = append(unlocked, c...)
	}

	if len(unlocked) == 0 {
		return fmt.Errorf("failed to unlock collection '%v'", collection)
	}

	return nil
}

func (s *SecretService) Close(session BusObject) error {
	return session.Call(sessionInterface+".Close", 0).Err
}

func (s *SecretService) CreateItem(collection BusObject, label string, attributes map[string]string, secret Secret) error {
	properties := map[string]Variant{
		itemInterface + ".Label":      MakeVariant(label),
		itemInterface + ".Attributes": MakeVariant(attributes),
	}

	var item, prompt ObjectPath
	err := collection.Call(collectionInterface+".CreateItem", 0, properties, secret, true).Store(&item, &prompt)
	if err != nil {
		return err
	}

	dismissed, _, err := s.handlePrompt(prompt)
	if err != nil {
		return err
	}
	if dismissed {
		return fmt.Errorf("prompt dismissed")
	}

	return nil
}

func (s *SecretService) handlePrompt(prompt ObjectPath) (bool, Variant, error) {
	if prompt != ObjectPath("/") {
		err := s.AddMatchSignal(prompt, promptInterface)
		if err != nil {
			return false, MakeVariant(""), err
		}

		defer func() {
			_ = s.RemoveMatchSignal(prompt, promptInterface)
		}()

		promptSignal := make(chan *Signal, 1)
		s.Signal(promptSignal)

		err = s.Object(serviceName, prompt).Call(promptInterface+".Prompt", 0, "").Err
		if err != nil {
			return false, MakeVariant(""), err
		}

		signal := <-promptSignal
		if signal.Name == promptInterface+".Completed" {
			if len(signal.Body) >= 2 {
				dismissed, _ := signal.Body[0].(bool)
				result, _ := signal.Body[1].(Variant)
				return dismissed, result, nil
			}
		}
	}

	return false, MakeVariant(""), nil
}

func (s *SecretService) SearchItems(collection BusObject, search map[string]string) ([]ObjectPath, error) {
	var results []ObjectPath
	err := collection.Call(collectionInterface+".SearchItems", 0, search).Store(&results)
	if err != nil {
		return nil, err
	}

	return results, nil
}

func (s *SecretService) GetSecret(itemPath ObjectPath, session ObjectPath) (*Secret, error) {
	var secret Secret
	err := s.Object(serviceName, itemPath).Call(itemInterface+".GetSecret", 0, session).Store(&secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

func (s *SecretService) Delete(itemPath ObjectPath) error {
	var prompt ObjectPath
	err := s.Object(serviceName, itemPath).Call(itemInterface+".Delete", 0).Store(&prompt)
	if err != nil {
		return err
	}

	dismissed, _, err := s.handlePrompt(prompt)
	if err != nil {
		return err
	}
	if dismissed {
		return fmt.Errorf("prompt dismissed")
	}

	return nil
}
