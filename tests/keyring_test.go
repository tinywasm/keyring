package keyring_test

import (
	"fmt"
	"testing"

	"github.com/tinywasm/keyring"
)

// memProvider is an in-memory Provider for tests: it replaces the OS keyring
// backend so nothing touches real credentials.
type memProvider struct {
	store map[string]map[string]string
}

func newMemProvider() *memProvider {
	return &memProvider{store: map[string]map[string]string{}}
}

func (p *memProvider) Set(service, user, password string) error {
	if p.store[service] == nil {
		p.store[service] = map[string]string{}
	}
	p.store[service][user] = password
	return nil
}

func (p *memProvider) Get(service, user string) (string, error) {
	if v, ok := p.store[service][user]; ok {
		return v, nil
	}
	return "", fmt.Errorf("secret %q not found for service %q", user, service)
}

func (p *memProvider) Delete(service, user string) error {
	if _, ok := p.store[service][user]; !ok {
		return fmt.Errorf("secret %q not found for service %q", user, service)
	}
	delete(p.store[service], user)
	return nil
}

func (p *memProvider) DeleteAll(service string) error {
	delete(p.store, service)
	return nil
}

// useMemProvider swaps the backend for the test and restores it afterwards.
func useMemProvider(t *testing.T) *memProvider {
	t.Helper()
	real := keyring.GetProvider()
	p := newMemProvider()
	keyring.SetProvider(p)
	t.Cleanup(func() { keyring.SetProvider(real) })
	return p
}

func TestKeyring_SetGetDelete(t *testing.T) {
	useMemProvider(t)

	kr, err := keyring.NewKeyring("test-service")
	if err != nil {
		t.Fatalf("NewKeyring failed: %v", err)
	}

	if err := kr.Set("my-key", "my-value"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got, err := kr.Get("my-key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got != "my-value" {
		t.Fatalf("got %q, want %q", got, "my-value")
	}

	if err := kr.Delete("my-key"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := kr.Get("my-key"); err == nil {
		t.Fatal("expected error after Delete")
	}
}

func TestKeyring_ServiceIsolation(t *testing.T) {
	useMemProvider(t)

	a, err := keyring.NewKeyring("app-a")
	if err != nil {
		t.Fatalf("NewKeyring app-a failed: %v", err)
	}
	b, err := keyring.NewKeyring("app-b")
	if err != nil {
		t.Fatalf("NewKeyring app-b failed: %v", err)
	}

	if err := a.Set("token", "value-a"); err != nil {
		t.Fatal(err)
	}
	if err := b.Set("token", "value-b"); err != nil {
		t.Fatal(err)
	}

	gotA, _ := a.Get("token")
	gotB, _ := b.Get("token")
	if gotA != "value-a" || gotB != "value-b" {
		t.Fatalf("services leaked into each other: a=%q b=%q", gotA, gotB)
	}
}

func TestKeyring_SetLog_IgnoresNil(t *testing.T) {
	useMemProvider(t)

	kr, err := keyring.NewKeyring("test-service")
	if err != nil {
		t.Fatal(err)
	}
	kr.SetLog(nil) // must not panic
	kr.SetLog(func(...any) {})
}

func TestOpenKeyring_IsLazy(t *testing.T) {
	// OpenKeyring must not probe or touch the backend at all.
	kr := keyring.OpenKeyring("lazy-service")
	if kr == nil {
		t.Fatal("expected a Keyring")
	}

	// Still a fully working store once the backend is in place.
	useMemProvider(t)
	if err := kr.Set("k", "v"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if got, _ := kr.Get("k"); got != "v" {
		t.Fatalf("got %q, want %q", got, "v")
	}
}

func TestKeyManager_RoundTrip(t *testing.T) {
	useMemProvider(t)

	km := keyring.New()
	if km.IsConfigured() {
		t.Fatal("expected not configured on empty keyring")
	}

	if err := km.Setup("hmac-1", "pat-1"); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	if !km.IsConfigured() {
		t.Fatal("expected configured after Setup")
	}

	hmac, err := km.GetHMACSecret()
	if err != nil {
		t.Fatalf("GetHMACSecret failed: %v", err)
	}
	if hmac != "hmac-1" {
		t.Fatalf("hmac=%q, want %q", hmac, "hmac-1")
	}
	pat, err := km.GetGitHubPAT()
	if err != nil {
		t.Fatalf("GetGitHubPAT failed: %v", err)
	}
	if pat != "pat-1" {
		t.Fatalf("pat=%q, want %q", pat, "pat-1")
	}

	if err := km.RotateHMACSecret("hmac-2"); err != nil {
		t.Fatalf("RotateHMACSecret failed: %v", err)
	}
	if err := km.RotateGitHubPAT("pat-2"); err != nil {
		t.Fatalf("RotateGitHubPAT failed: %v", err)
	}
	if hmac, _ := km.GetHMACSecret(); hmac != "hmac-2" {
		t.Fatalf("rotated hmac=%q", hmac)
	}

	if err := km.DeleteAll(); err != nil {
		t.Fatalf("DeleteAll failed: %v", err)
	}
	if km.IsConfigured() {
		t.Fatal("expected not configured after DeleteAll")
	}
	if _, err := km.GetGitHubPAT(); err == nil {
		t.Fatal("expected error reading PAT after DeleteAll")
	}
}