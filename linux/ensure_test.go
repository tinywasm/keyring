package linux

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestEnsureOrderAndSuccess(t *testing.T) {
	p := New()
	var runCalls []string

	p.lookPathFn = func(file string) (string, error) {
		if file == "apt" || file == "gnome-keyring-daemon" {
			return "/usr/bin/" + file, nil
		}
		return "", errors.New("not found")
	}

	p.runFn = func(name string, args ...string) error {
		runCalls = append(runCalls, fmt.Sprintf("%s %s", name, strings.Join(args, " ")))
		return nil
	}

	err := p.Ensure(func(a ...any) {})
	if err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}

	if len(runCalls) != 1 {
		t.Fatalf("Expected 1 run call, got %d", len(runCalls))
	}

	expected := "sudo apt install -y gnome-keyring libsecret-1-0"
	if runCalls[0] != expected {
		t.Errorf("Expected run call %q, got %q", expected, runCalls[0])
	}
}

func TestEnsureManualInstallMessageWhenAllFail(t *testing.T) {
	p := New()
	p.lookPathFn = func(file string) (string, error) {
		return "", errors.New("not found")
	}

	err := p.Ensure(func(a ...any) {})
	if err == nil {
		t.Fatal("Expected error when no package manager exists, got nil")
	}

	expectedMsg := "could not install keyring. Install manually:"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Expected manual install message %q in error %q", expectedMsg, err.Error())
	}
}
