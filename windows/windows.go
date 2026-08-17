//go:build windows

package windows

import (
	"strings"
	"syscall"
	"unsafe"

	"github.com/tinywasm/keyring"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCredReadW      = advapi32.NewProc("CredReadW")
	procCredWriteW     = advapi32.NewProc("CredWriteW")
	procCredDeleteW    = advapi32.NewProc("CredDeleteW")
	procCredEnumerateW = advapi32.NewProc("CredEnumerateW")
	procCredFree       = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
	errorNotFound           = syscall.Errno(1168) // ERROR_NOT_FOUND
)

type filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type Provider struct{}

func New() *Provider { return &Provider{} }

func (p *Provider) Get(service, user string) (string, error) {
	target := CredName(service, user)
	targetPtr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return "", keyring.Wrap("keyring/windows: UTF16PtrFromString", err)
	}

	var pCred *credential
	r1, _, lastErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&pCred)),
	)
	if r1 == 0 {
		if lastErr == errorNotFound {
			return "", keyring.ErrNotFound
		}
		return "", keyring.Wrap("keyring/windows: CredReadW", lastErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pCred)))

	blob := make([]byte, pCred.CredentialBlobSize)
	if pCred.CredentialBlobSize > 0 {
		copy(blob, unsafe.Slice(pCred.CredentialBlob, pCred.CredentialBlobSize))
	}
	return string(blob), nil
}

func (p *Provider) Set(service, user, password string) error {
	if err := ValidateTargetAndBlob(service, password); err != nil {
		return err
	}

	target := CredName(service, user)
	targetPtr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return keyring.Wrap("keyring/windows: UTF16PtrFromString target", err)
	}

	userPtr, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return keyring.Wrap("keyring/windows: UTF16PtrFromString user", err)
	}

	var passBytes []byte
	var passPtr *byte
	if len(password) > 0 {
		passBytes = []byte(password)
		passPtr = &passBytes[0]
	}

	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         targetPtr,
		CredentialBlobSize: uint32(len(passBytes)),
		CredentialBlob:     passPtr,
		Persist:            credPersistLocalMachine,
		UserName:           userPtr,
	}

	r1, _, lastErr := procCredWriteW.Call(
		uintptr(unsafe.Pointer(&cred)),
		0,
	)
	if r1 == 0 {
		return keyring.Wrap("keyring/windows: CredWriteW", lastErr)
	}
	return nil
}

func (p *Provider) Delete(service, user string) error {
	target := CredName(service, user)
	targetPtr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return keyring.Wrap("keyring/windows: UTF16PtrFromString", err)
	}

	r1, _, lastErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
	)
	if r1 == 0 {
		if lastErr == errorNotFound {
			return keyring.ErrNotFound
		}
		return keyring.Wrap("keyring/windows: CredDeleteW", lastErr)
	}
	return nil
}

func (p *Provider) DeleteAll(service string) error {
	if service == "" {
		return keyring.ErrNotFound
	}

	var count uint32
	var pCreds **credential
	r1, _, lastErr := procCredEnumerateW.Call(
		0,
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&pCreds)),
	)
	if r1 == 0 {
		if lastErr == errorNotFound {
			return nil
		}
		return keyring.Wrap("keyring/windows: CredEnumerateW", lastErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pCreds)))

	creds := unsafe.Slice(pCreds, count)
	prefix := CredName(service, "")

	for _, credPtr := range creds {
		if credPtr == nil || credPtr.TargetName == nil {
			continue
		}
		targetName := syscall.UTF16ToString(unsafe.Slice(credPtr.TargetName, 512))
		if strings.HasPrefix(targetName, prefix) {
			tPtr, err := syscall.UTF16PtrFromString(targetName)
			if err != nil {
				continue
			}
			r1Del, _, _ := procCredDeleteW.Call(
				uintptr(unsafe.Pointer(tPtr)),
				uintptr(credTypeGeneric),
				0,
			)
			_ = r1Del
		}
	}
	return nil
}
