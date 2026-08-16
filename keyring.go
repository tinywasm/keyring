package keyring

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Keyring provides scoped credential storage through the system keyring.
// The service name is a namespace: the same key under different services
// never collides, so one process can hold secrets for several apps.
type Keyring struct {
	service string
	log     func(...any)
}

// NewKeyring creates a Keyring scoped to service and verifies the system
// keyring actually works, installing its dependencies on Linux when missing.
func NewKeyring(service string) (*Keyring, error) {
	k := &Keyring{
		service: service,
		log:     func(...any) {},
	}
	if err := k.ensureKeyringAvailable(); err != nil {
		return nil, err
	}
	return k, nil
}

// OpenKeyring creates a Keyring scoped to service without probing the system
// keyring: nothing touches the OS until the first Get/Set/Delete. Use it when
// the store is only needed conditionally (e.g. session recovery) or in flows
// that may legitimately run without a keyring (CI with GH_TOKEN).
func OpenKeyring(service string) *Keyring {
	return &Keyring{
		service: service,
		log:     func(...any) {},
	}
}

// SetLog sets the logging function.
func (k *Keyring) SetLog(fn func(...any)) {
	if fn != nil {
		k.log = fn
	}
}

// Set stores value under key in this service's namespace.
func (k *Keyring) Set(key, value string) error {
	return currentProvider.Set(k.service, key, value)
}

// Get returns the value stored under key in this service's namespace.
func (k *Keyring) Get(key string) (string, error) {
	return currentProvider.Get(k.service, key)
}

// Delete removes key from this service's namespace.
func (k *Keyring) Delete(key string) error {
	return currentProvider.Delete(k.service, key)
}

// ensureKeyringAvailable checks that the keyring works and installs
// dependencies if needed.
func (k *Keyring) ensureKeyringAvailable() error {
	// Test if keyring is working
	testKey := "keyring_test_probe"
	err := currentProvider.Set(k.service, testKey, "test")
	if err == nil {
		currentProvider.Delete(k.service, testKey)
		return nil
	}

	// Keyring failed - try to install on Linux only
	if runtime.GOOS != "linux" {
		return fmt.Errorf("keyring unavailable: %w", err)
	}

	k.log("⚙️  Installing keyring dependencies...")

	if !k.tryInstallKeyring() {
		return fmt.Errorf("could not install keyring. Install manually:\n  Debian/Ubuntu: sudo apt install gnome-keyring libsecret-1-0\n  Fedora: sudo dnf install gnome-keyring libsecret\n  Arch: sudo pacman -S gnome-keyring libsecret")
	}

	k.startKeyringService()

	// Test again
	err = currentProvider.Set(k.service, testKey, "test")
	if err == nil {
		currentProvider.Delete(k.service, testKey)
		k.log("✅ Keyring installed successfully")
		return nil
	}

	return fmt.Errorf("keyring installation failed: %w", err)
}

// tryInstallKeyring attempts to install keyring using the available package manager.
func (k *Keyring) tryInstallKeyring() bool {
	type pkgManager struct {
		cmd  string
		args []string
	}

	managers := []pkgManager{
		{"apt", []string{"sudo", "apt", "install", "-y", "gnome-keyring", "libsecret-1-0"}},
		{"dnf", []string{"sudo", "dnf", "install", "-y", "gnome-keyring", "libsecret"}},
		{"pacman", []string{"sudo", "pacman", "-S", "--noconfirm", "gnome-keyring", "libsecret"}},
	}

	for _, m := range managers {
		if _, err := exec.LookPath(m.cmd); err == nil {
			k.log(fmt.Sprintf("   Installing via %s...", m.cmd))
			cmd := exec.Command(m.args[0], m.args[1:]...)
			// We don't pipe to os.Stdout anymore to keep it quiet unless logged
			if cmd.Run() == nil {
				return true
			}
		}
	}
	return false
}

// startKeyringService starts gnome-keyring-daemon if not running.
func (k *Keyring) startKeyringService() {
	if _, err := exec.LookPath("gnome-keyring-daemon"); err != nil {
		return
	}

	cmd := exec.Command("gnome-keyring-daemon", "--start", "--components=secrets")
	output, err := cmd.Output()
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
	}
}