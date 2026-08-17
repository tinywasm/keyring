package darwin

import (
	"encoding/base64"
	"strings"

	"github.com/tinywasm/keyring"
)

const (
	execPathKeychain = "/usr/bin/security"
	valuePrefix      = "tw-keyring-b64:"
	notFoundMarker   = "could not be found"
	maxCommandBytes  = 4096
)

// Quote renders s as a single shell-safe token for security(1)'s interactive parser.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if !needsQuoting(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func needsQuoting(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '_', '@', '%', '+', '=', ':', ',', '.', '/', '-':
			continue
		default:
			return true
		}
	}
	return false
}

// EncodeValue encodes the value with the tw-keyring-b64: prefix.
func EncodeValue(password string) string {
	return valuePrefix + base64.StdEncoding.EncodeToString([]byte(password))
}

// DecodeValue decodes tw-keyring-b64: formatted strings or returns s if unencoded.
func DecodeValue(s string) (string, error) {
	if strings.HasPrefix(s, valuePrefix) {
		dec, err := base64.StdEncoding.DecodeString(s[len(valuePrefix):])
		if err != nil {
			return "", keyring.Wrap("keyring/darwin: decode base64", err)
		}
		return string(dec), nil
	}
	return s, nil
}

// ValidateCommandLength checks if the formatted command line is within maxCommandBytes.
func ValidateCommandLength(cmdStr string) error {
	if len(cmdStr) > maxCommandBytes {
		return keyring.ErrTooBig
	}
	return nil
}
