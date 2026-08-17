package darwin

import (
	"errors"
	"strings"
	"testing"

	"github.com/tinywasm/keyring"
)

func TestQuote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "abc"},
		{"", "''"},
		{"a b", "'a b'"},
		{"it's", `'it'"'"'s'`},
		{"$(rm -rf /)", "'$(rm -rf /)'"},
		{"a/b-c.d_e", "a/b-c.d_e"},
	}

	for _, tt := range tests {
		got := Quote(tt.input)
		if got != tt.expected {
			t.Errorf("Quote(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestEncodeDecodeValue(t *testing.T) {
	input := "línea1\nlínea2"
	encoded := EncodeValue(input)
	decoded, err := DecodeValue(encoded)
	if err != nil {
		t.Fatalf("DecodeValue failed: %v", err)
	}
	if decoded != input {
		t.Errorf("Expected %q, got %q", input, decoded)
	}

	plain, err := DecodeValue("plain")
	if err != nil {
		t.Fatalf("DecodeValue plain failed: %v", err)
	}
	if plain != "plain" {
		t.Errorf("Expected plain, got %q", plain)
	}
}

func TestValidateCommandLength(t *testing.T) {
	cmd := "add-generic-password -U " + strings.Repeat("a", 4100)
	if err := ValidateCommandLength(cmd); !errors.Is(err, keyring.ErrTooBig) {
		t.Errorf("Expected ErrTooBig, got %v", err)
	}
}
