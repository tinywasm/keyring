package linux

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var packageManagers = []struct {
	cmd  string
	args []string
}{
	{"apt", []string{"sudo", "apt", "install", "-y", "gnome-keyring", "libsecret-1-0"}},
	{"dnf", []string{"sudo", "dnf", "install", "-y", "gnome-keyring", "libsecret"}},
	{"pacman", []string{"sudo", "pacman", "-S", "--noconfirm", "gnome-keyring", "libsecret"}},
}

func (p *Provider) Ensure(log func(...any)) error {
	if log == nil {
		log = func(...any) {}
	}
	log("⚙️  Installing keyring dependencies...")

	installed := false
	for _, pm := range packageManagers {
		if _, err := p.lookPath(pm.cmd); err == nil {
			log(fmt.Sprintf("   Installing via %s...", pm.cmd))
			if err := p.run(pm.args[0], pm.args[1:]...); err == nil {
				installed = true
				break
			}
		}
	}

	if !installed {
		return fmt.Errorf("could not install keyring. Install manually:\n  Debian/Ubuntu: sudo apt install gnome-keyring libsecret-1-0\n  Fedora: sudo dnf install gnome-keyring libsecret\n  Arch: sudo pacman -S gnome-keyring libsecret")
	}

	p.startKeyringDaemon()
	return nil
}

func (p *Provider) startKeyringDaemon() {
	if _, err := p.lookPath("gnome-keyring-daemon"); err != nil {
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

func (p *Provider) lookPath(file string) (string, error) {
	if p.lookPathFn != nil {
		return p.lookPathFn(file)
	}
	return exec.LookPath(file)
}

func (p *Provider) run(name string, args ...string) error {
	if p.runFn != nil {
		return p.runFn(name, args...)
	}
	cmd := exec.Command(name, args...)
	return cmd.Run()
}
