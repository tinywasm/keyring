package linux

import (
	"fmt"

	"github.com/tinywasm/keyring"
)

type Provider struct {
	conn       *Conn
	runFn      func(name string, args ...string) error
	lookPathFn func(file string) (string, error)
}

func New() *Provider {
	return &Provider{}
}

func NewOnConn(conn *Conn) *Provider {
	return &Provider{conn: conn}
}

func (p *Provider) getService() (*SecretService, error) {
	if p.conn != nil {
		return NewSecretServiceOnConn(p.conn), nil
	}
	return NewSecretService()
}

func (p *Provider) Set(service, user, password string) error {
	svc, err := p.getService()
	if err != nil {
		return keyring.Wrap("keyring/linux: NewSecretService", err)
	}
	if p.conn == nil {
		defer svc.CloseConn()
	}

	session, err := svc.OpenSession()
	if err != nil {
		return keyring.Wrap("keyring/linux: OpenSession", err)
	}
	defer svc.Close(session)

	attributes := map[string]string{
		"username": user,
		"service":  service,
	}

	secret := NewSecret(session.Path(), password)
	collection := svc.GetLoginCollection()

	if err := svc.Unlock(collection.Path()); err != nil {
		return keyring.Wrap("keyring/linux: Unlock collection", err)
	}

	label := fmt.Sprintf("Password for '%s' on '%s'", user, service)
	if err := svc.CreateItem(collection, label, attributes, secret); err != nil {
		return keyring.Wrap("keyring/linux: CreateItem", err)
	}

	return nil
}

func (p *Provider) Get(service, user string) (string, error) {
	svc, err := p.getService()
	if err != nil {
		return "", keyring.Wrap("keyring/linux: NewSecretService", err)
	}
	if p.conn == nil {
		defer svc.CloseConn()
	}

	itemPath, err := p.findItem(svc, service, user)
	if err != nil {
		return "", err
	}

	session, err := svc.OpenSession()
	if err != nil {
		return "", keyring.Wrap("keyring/linux: OpenSession", err)
	}
	defer svc.Close(session)

	if err := svc.Unlock(itemPath); err != nil {
		return "", keyring.Wrap("keyring/linux: Unlock item", err)
	}

	secret, err := svc.GetSecret(itemPath, session.Path())
	if err != nil {
		return "", keyring.Wrap("keyring/linux: GetSecret", err)
	}

	return string(secret.Value), nil
}

func (p *Provider) Delete(service, user string) error {
	svc, err := p.getService()
	if err != nil {
		return keyring.Wrap("keyring/linux: NewSecretService", err)
	}
	if p.conn == nil {
		defer svc.CloseConn()
	}

	itemPath, err := p.findItem(svc, service, user)
	if err != nil {
		return err
	}

	if err := svc.Delete(itemPath); err != nil {
		return keyring.Wrap("keyring/linux: Delete", err)
	}
	return nil
}

func (p *Provider) DeleteAll(service string) error {
	if service == "" {
		return keyring.ErrNotFound
	}

	svc, err := p.getService()
	if err != nil {
		return keyring.Wrap("keyring/linux: NewSecretService", err)
	}
	if p.conn == nil {
		defer svc.CloseConn()
	}

	items, err := p.findServiceItems(svc, service)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil
		}
		return err
	}

	for _, itemPath := range items {
		if err := svc.Delete(itemPath); err != nil {
			return keyring.Wrap("keyring/linux: DeleteAll", err)
		}
	}
	return nil
}

func (p *Provider) findItem(svc *SecretService, service, user string) (ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"username": user,
		"service":  service,
	}

	if err := svc.Unlock(collection.Path()); err != nil {
		return "", keyring.Wrap("keyring/linux: Unlock collection", err)
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return "", keyring.Wrap("keyring/linux: SearchItems", err)
	}

	if len(results) == 0 {
		return "", keyring.ErrNotFound
	}

	return results[0], nil
}

func (p *Provider) findServiceItems(svc *SecretService, service string) ([]ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"service": service,
	}

	if err := svc.Unlock(collection.Path()); err != nil {
		return nil, keyring.Wrap("keyring/linux: Unlock collection", err)
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return nil, keyring.Wrap("keyring/linux: SearchItems", err)
	}

	if len(results) == 0 {
		return nil, keyring.ErrNotFound
	}

	return results, nil
}

