package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"
)

var unlockSocket = "/run/workspace/unlock.sock"

func ownerSSHKey(value string) (string, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if !ok || err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != encoded {
		return "", errors.New("SANDBOX_OWNER_PUBLIC_KEY must be ed25519: followed by a base64 public key")
	}
	key, err := ssh.NewPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		return "", err
	}
	return string(ssh.MarshalAuthorizedKey(key)), nil
}

// OpenSSH supplies stdin after authenticating the measured owner. The Unix socket
// is accessible only to that account and root; it is never exposed through HTTP.
func forwardUnlock(input io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(input, maxEnrollBytes+1))
	defer clear(data)
	if err != nil {
		return err
	}
	if len(data) > maxEnrollBytes {
		return errors.New("unlock request is too large")
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: volumeTimeout}).DialContext(ctx, "unix", unlockSocket)
	}}}
	defer client.CloseIdleConnections()
	response, err := client.Post("http://workspace/unlock", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("workspace unlock unavailable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("unlock refused: %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	return nil
}
