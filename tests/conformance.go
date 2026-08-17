package tests

import (
	"errors"
	"strings"
	"testing"

	"github.com/tinywasm/keyring"
)

// RunConformance asserts the full Provider contract against p. Every backend
// must pass it: the in-memory provider, each native backend on its own
// platform, and the browser backend under TinyGo.
//
// skipTooBig is true for backends with no size limit (Linux, in-memory), where
// the oversized-value case does not apply.
func RunConformance(t *testing.T, p keyring.Provider, skipTooBig bool) {
	const user = "test-user"
	const password = "test-password"

	t.Run("Set", func(t *testing.T) {
		svc := t.Name()
		err := p.Set(svc, user, password)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}
	})

	t.Run("SetTooLong", func(t *testing.T) {
		if skipTooBig {
			t.Skip("skipping size limit check for backend without limit")
		}
		svc := t.Name()
		extraLongPassword := "ba" + strings.Repeat("na", 5000)
		err := p.Set(svc, user, extraLongPassword)
		if !errors.Is(err, keyring.ErrTooBig) {
			t.Errorf("Expected ErrTooBig, got: %v", err)
		}
	})

	t.Run("GetMultiLine", func(t *testing.T) {
		svc := t.Name()
		multilinePassword := `this password
has multiple
lines and will be
encoded by some keyring implementiations
like osx`
		err := p.Set(svc, user, multilinePassword)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		pw, err := p.Get(svc, user)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		if multilinePassword != pw {
			t.Errorf("Expected password %s, got %s", multilinePassword, pw)
		}
	})

	t.Run("GetUmlaut", func(t *testing.T) {
		svc := t.Name()
		umlautPassword := "at least on OSX üöäÜÖÄß will be encoded"
		err := p.Set(svc, user, umlautPassword)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		pw, err := p.Get(svc, user)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		if umlautPassword != pw {
			t.Errorf("Expected password %s, got %s", umlautPassword, pw)
		}
	})

	t.Run("GetSingleLineHex", func(t *testing.T) {
		svc := t.Name()
		hexPassword := "abcdef123abcdef123"
		err := p.Set(svc, user, hexPassword)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		pw, err := p.Get(svc, user)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		if hexPassword != pw {
			t.Errorf("Expected password %s, got %s", hexPassword, pw)
		}
	})

	t.Run("Get", func(t *testing.T) {
		svc := t.Name()
		err := p.Set(svc, user, password)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		pw, err := p.Get(svc, user)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		if password != pw {
			t.Errorf("Expected password %s, got %s", password, pw)
		}
	})

	t.Run("GetNonExisting", func(t *testing.T) {
		svc := t.Name()
		_, err := p.Get(svc, user+"fake")
		if !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		svc := t.Name()
		err := p.Set(svc, user, password)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		err = p.Delete(svc, user)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		_, err = p.Get(svc, user)
		if !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("Expected ErrNotFound after delete, got %v", err)
		}
	})

	t.Run("DeleteNonExisting", func(t *testing.T) {
		svc := t.Name()
		err := p.Delete(svc, user+"fake")
		if !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}
	})

	t.Run("DeleteAll", func(t *testing.T) {
		svc := t.Name()
		err := p.Set(svc, user, password)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		err = p.Set(svc, user+"2", password+"2")
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		err = p.DeleteAll(svc)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		_, err = p.Get(svc, user)
		if !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}

		_, err = p.Get(svc, user+"2")
		if !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}

		err = p.DeleteAll(svc)
		if err != nil {
			t.Errorf("Should not fail on empty service, got: %v", err)
		}
	})

	t.Run("DeleteAllEmptyService", func(t *testing.T) {
		svc := t.Name()
		err := p.Set(svc, user, password)
		if err != nil {
			t.Fatalf("Should not fail, got: %v", err)
		}

		_ = p.DeleteAll("")
		_, err = p.Get(svc, user)
		if errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("Should not have deleted secret from another service")
		}
	})
}
