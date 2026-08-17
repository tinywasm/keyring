package windows

import (
	"errors"
	"strings"
	"testing"

	"github.com/tinywasm/keyring"
)

func TestCredName(t *testing.T) {
	tests := []struct {
		service  string
		user     string
		expected string
	}{
		{"devflow", "github-pat", "devflow:github-pat"},
		{"devflow", "", "devflow:"},
		{"", "x", ":x"},
	}

	for _, tt := range tests {
		got := CredName(tt.service, tt.user)
		if got != tt.expected {
			t.Errorf("CredName(%q, %q) = %q; want %q", tt.service, tt.user, got, tt.expected)
		}
	}
}

func TestValidateTargetAndBlob(t *testing.T) {
	if err := ValidateTargetAndBlob("service", "password"); err != nil {
		t.Errorf("Expected nil for valid inputs, got %v", err)
	}

	longPass := strings.Repeat("a", maxBlobBytes+1)
	if err := ValidateTargetAndBlob("service", longPass); !errors.Is(err, keyring.ErrTooBig) {
		t.Errorf("Expected ErrTooBig for long password, got %v", err)
	}

	longSvc := strings.Repeat("s", maxTargetBytes)
	if err := ValidateTargetAndBlob(longSvc, "password"); !errors.Is(err, keyring.ErrTooBig) {
		t.Errorf("Expected ErrTooBig for long service, got %v", err)
	}
}

func TestMatchesPrefix(t *testing.T) {
	if !MatchesPrefix("devflow", "devflow:user1") {
		t.Errorf("Expected match for devflow:user1")
	}
	if MatchesPrefix("devflow", "other:user1") {
		t.Errorf("Expected no match for other:user1")
	}
}
