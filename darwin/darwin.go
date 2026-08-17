// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin

package darwin

import (
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/tinywasm/keyring"
)

type Provider struct{}

func New() *Provider { return &Provider{} }

func (p *Provider) Get(service, user string) (string, error) {
	out, err := exec.Command(
		execPathKeychain,
		"find-generic-password",
		"-s", service,
		"-wa", user,
	).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), notFoundMarker) {
			return "", keyring.ErrNotFound
		}
		return "", keyring.Wrap("keyring/darwin: find-generic-password", err)
	}

	trimStr := strings.TrimSpace(string(out))
	val, err := DecodeValue(trimStr)
	if err != nil {
		return "", err
	}
	return val, nil
}

func (p *Provider) Set(service, user, password string) error {
	encodedPass := EncodeValue(password)
	cmdStr := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n",
		Quote(service), Quote(user), Quote(encodedPass))

	if err := ValidateCommandLength(cmdStr); err != nil {
		return err
	}

	cmd := exec.Command(execPathKeychain, "-i")
	stdIn, err := cmd.StdinPipe()
	if err != nil {
		return keyring.Wrap("keyring/darwin: StdinPipe", err)
	}

	if err = cmd.Start(); err != nil {
		return keyring.Wrap("keyring/darwin: cmd.Start", err)
	}

	if _, err := io.WriteString(stdIn, cmdStr); err != nil {
		return keyring.Wrap("keyring/darwin: WriteString", err)
	}

	if err = stdIn.Close(); err != nil {
		return keyring.Wrap("keyring/darwin: stdIn.Close", err)
	}

	if err = cmd.Wait(); err != nil {
		return keyring.Wrap("keyring/darwin: cmd.Wait", err)
	}
	return nil
}

func (p *Provider) Delete(service, user string) error {
	out, err := exec.Command(
		execPathKeychain,
		"delete-generic-password",
		"-s", service,
		"-a", user,
	).CombinedOutput()
	if strings.Contains(string(out), notFoundMarker) {
		return keyring.ErrNotFound
	}
	if err != nil {
		return keyring.Wrap("keyring/darwin: delete-generic-password", err)
	}
	return nil
}

func (p *Provider) DeleteAll(service string) error {
	if service == "" {
		return keyring.ErrNotFound
	}

	for i := 0; i < 1000; i++ {
		out, err := exec.Command(
			execPathKeychain,
			"delete-generic-password",
			"-s", service,
		).CombinedOutput()

		if strings.Contains(string(out), notFoundMarker) {
			return nil
		}
		if err != nil {
			return keyring.Wrap("keyring/darwin: delete-generic-password all", err)
		}
	}
	return keyring.ErrUnavailable
}
