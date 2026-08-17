package tests

import (
	"errors"
	"testing"

	"github.com/tinywasm/keyring"
	auto "github.com/tinywasm/keyring/auto"
)

type ensurerMemProvider struct {
	MemProvider
	ensureCalls int
	probeFail   bool
}

func (e *ensurerMemProvider) Set(service, user, pass string) error {
	if e.probeFail && user == "keyring_test_probe" {
		return keyring.ErrUnavailable
	}
	return e.MemProvider.Set(service, user, pass)
}

func (e *ensurerMemProvider) Ensure(log func(...any)) error {
	e.ensureCalls++
	e.probeFail = false
	return nil
}

func TestConformanceMem(t *testing.T) {
	RunConformance(t, NewMemProvider(), true)
}

func TestNilProvider(t *testing.T) {
	kr := keyring.OpenKeyring("svc", nil)
	if err := kr.Set("k", "v"); !errors.Is(err, keyring.ErrNoProvider) {
		t.Errorf("Expected ErrNoProvider from Set, got %v", err)
	}
	if _, err := kr.Get("k"); !errors.Is(err, keyring.ErrNoProvider) {
		t.Errorf("Expected ErrNoProvider from Get, got %v", err)
	}
	if err := kr.Delete("k"); !errors.Is(err, keyring.ErrNoProvider) {
		t.Errorf("Expected ErrNoProvider from Delete, got %v", err)
	}

	_, err := keyring.NewKeyring("svc", nil)
	if !errors.Is(err, keyring.ErrNoProvider) {
		t.Errorf("Expected ErrNoProvider from NewKeyring, got %v", err)
	}
}

func TestEnsureRunsWhenProbeFails(t *testing.T) {
	p := &ensurerMemProvider{
		MemProvider: *NewMemProvider(),
		probeFail:   true,
	}
	kr, err := keyring.NewKeyring("svc", p)
	if err != nil {
		t.Fatalf("Expected NewKeyring success after ensure, got %v", err)
	}
	if kr == nil {
		t.Fatalf("Expected non-nil keyring")
	}
	if p.ensureCalls != 1 {
		t.Errorf("Expected ensureCalls to be 1, got %d", p.ensureCalls)
	}
}

func TestEnsureNeverRunsWhenProbeSucceeds(t *testing.T) {
	p := &ensurerMemProvider{
		MemProvider: *NewMemProvider(),
		probeFail:   false,
	}
	_, err := keyring.NewKeyring("svc", p)
	if err != nil {
		t.Fatalf("Expected NewKeyring success, got %v", err)
	}
	if p.ensureCalls != 0 {
		t.Errorf("Expected ensureCalls to be 0, got %d", p.ensureCalls)
	}
}

func TestBackendWithoutEnsurerYieldsErrUnavailable(t *testing.T) {
	p := NewMemProvider()
	p.Err = keyring.ErrUnavailable
	_, err := keyring.NewKeyring("svc", p)
	if !errors.Is(err, keyring.ErrUnavailable) {
		t.Errorf("Expected ErrUnavailable, got %v", err)
	}
}

func TestOpenKeyringNeverProbes(t *testing.T) {
	p := NewMemProvider()
	p.Err = errors.New("should never be called")
	kr := keyring.OpenKeyring("svc", p)
	if kr == nil {
		t.Fatal("OpenKeyring returned nil")
	}
}

func TestIndependentProviders(t *testing.T) {
	t.Parallel()
	p1 := NewMemProvider()
	p2 := NewMemProvider()

	kr1 := keyring.OpenKeyring("svc", p1)
	kr2 := keyring.OpenKeyring("svc", p2)

	if err := kr1.Set("key", "val1"); err != nil {
		t.Fatalf("kr1.Set failed: %v", err)
	}
	if err := kr2.Set("key", "val2"); err != nil {
		t.Fatalf("kr2.Set failed: %v", err)
	}

	v1, err := kr1.Get("key")
	if err != nil || v1 != "val1" {
		t.Errorf("kr1.Get expected val1, got %s (err %v)", v1, err)
	}
	v2, err := kr2.Get("key")
	if err != nil || v2 != "val2" {
		t.Errorf("kr2.Get expected val2, got %s (err %v)", v2, err)
	}
}

func TestFallback(t *testing.T) {
	fb := keyring.Fallback{}
	if err := fb.Set("s", "u", "p"); !errors.Is(err, keyring.ErrUnsupported) {
		t.Errorf("Expected ErrUnsupported from Set, got %v", err)
	}
	if _, err := fb.Get("s", "u"); !errors.Is(err, keyring.ErrUnsupported) {
		t.Errorf("Expected ErrUnsupported from Get, got %v", err)
	}
	if err := fb.Delete("s", "u"); !errors.Is(err, keyring.ErrUnsupported) {
		t.Errorf("Expected ErrUnsupported from Delete, got %v", err)
	}
	if err := fb.DeleteAll("s"); !errors.Is(err, keyring.ErrUnsupported) {
		t.Errorf("Expected ErrUnsupported from DeleteAll, got %v", err)
	}
}

func TestAutoDropInSignatures(t *testing.T) {
	_ = auto.OpenKeyring("probe")
	_, _ = auto.NewKeyring("probe")
	_ = auto.New()
}
