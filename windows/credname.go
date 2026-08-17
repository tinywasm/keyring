package windows

import (
	"strings"

	"github.com/tinywasm/keyring"
)

const (
	maxBlobBytes   = 2560
	maxTargetBytes = 512
)

// CredName combines service and username to a single string target.
func CredName(service, username string) string {
	return service + ":" + username
}

// ValidateTargetAndBlob checks size limits according to Windows Credential Manager constraints.
func ValidateTargetAndBlob(service, password string) error {
	if len(password) > maxBlobBytes {
		return keyring.ErrTooBig
	}
	if len(service) >= maxTargetBytes {
		return keyring.ErrTooBig
	}
	if len(service) > 1024*30 {
		return keyring.ErrTooBig
	}
	return nil
}

// MatchesPrefix checks if targetName belongs to service.
func MatchesPrefix(service, targetName string) bool {
	prefix := CredName(service, "")
	return strings.HasPrefix(targetName, prefix)
}
