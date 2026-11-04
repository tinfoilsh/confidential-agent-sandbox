package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func testWorkspace(t *testing.T) (*workspace, enrollInput, []byte) {
	t.Helper()
	dir := t.TempDir()
	unlock := filepath.Join(dir, "unlock")
	script := "#!/bin/sh\nset -eu\ndir=$(dirname \"$0\")\nif [ \"${1-}\" = --status ]; then cat \"$dir/state\"; else cat > \"$dir/key\"; printf unlocked > \"$dir/state\"; fi\n"
	if err := os.WriteFile(unlock, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state"), []byte("locked"), 0o600); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	disk := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(disk); err != nil {
		t.Fatal(err)
	}
	in := enrollInput{MonitorIdentitySeed: base64.RawURLEncoding.EncodeToString(private.Seed()),
		MonitorHostKey: authorizedKey(key), DiskKey: base64.RawURLEncoding.EncodeToString(disk), AllowInitialize: true}
	w := &workspace{instance: "22222222-2222-4222-8222-222222222222", monitor: filepath.Join(dir, "monitor"),
		uid: os.Getuid(), gid: os.Getgid(), unlock: unlock, network: func(context.Context) error { return nil }}
	return w, in, disk
}

func TestOwnerCommandSharesEnrollmentState(t *testing.T) {
	w, in, disk := testWorkspace(t)
	command := func(operation string, body []byte) status {
		t.Helper()
		var output bytes.Buffer
		if err := w.command(t.Context(), operation, bytes.NewReader(body), &output); err != nil {
			t.Fatal(err)
		}
		var result status
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Protocol != ownerProtocol || result.InstanceID != w.instance {
			t.Fatal("wrong workspace binding")
		}
		return result
	}
	if got := command(ownerStatus, nil); got.Volume != "locked" || got.MonitorIdentity != nil {
		t.Fatalf("unexpected initial state: %+v", got)
	}
	body, _ := json.Marshal(in)
	got := command(ownerEnroll, body)
	if got.Volume != "unlocked" || got.MonitorIdentity == nil || got.MonitorHostKey == nil || *got.MonitorHostKey != in.MonitorHostKey {
		t.Fatalf("unexpected enrolled state: %+v", got)
	}
	received, err := os.ReadFile(filepath.Join(filepath.Dir(w.unlock), "key"))
	if err != nil || !bytes.Equal(received, disk) {
		t.Fatal("the volume worker did not receive the disk key")
	}
	identity, err := os.ReadFile(filepath.Join(w.monitor, agentIdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	if repeated := command(ownerEnroll, body); *repeated.MonitorIdentity != *got.MonitorIdentity {
		t.Fatal("repeat enrollment replaced the Monitor identity")
	}
	otherSeed := make([]byte, ed25519.SeedSize)
	rand.Read(otherSeed)
	in.MonitorIdentitySeed = base64.RawURLEncoding.EncodeToString(otherSeed)
	body, _ = json.Marshal(in)
	var output bytes.Buffer
	if err := w.command(t.Context(), ownerEnroll, bytes.NewReader(body), &output); !errors.Is(err, errIdentityConflict) {
		t.Fatalf("expected identity conflict, got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(w.monitor, agentIdentityFile))
	if err != nil || !bytes.Equal(identity, after) || output.Len() != 0 {
		t.Fatal("refused enrollment changed the identity or reported success")
	}
}

func TestOwnerCommandRejectsInvalidInput(t *testing.T) {
	for _, body := range []string{"{", `{}`, `{"ignored":"` + strings.Repeat("x", maxOwnerBytes) + `"}`} {
		w, _, _ := testWorkspace(t)
		var output bytes.Buffer
		if err := w.command(t.Context(), ownerEnroll, strings.NewReader(body), &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid enrollment reported success")
		}
		if _, err := os.Stat(w.monitor); !os.IsNotExist(err) {
			t.Fatal("invalid enrollment wrote Monitor credentials")
		}
	}
}

func TestBrowserEnrollmentHoldsSharedFileLock(t *testing.T) {
	w, in, _ := testWorkspace(t)
	entered, release := make(chan struct{}), make(chan struct{})
	w.network = func(context.Context) error { close(entered); <-release; return nil }
	body, _ := json.Marshal(in)
	owner := &ownerServer{workspace: w}
	effect := owner.route(Call{Method: http.MethodPost, Path: "/enroll", Body: body})
	if effect == nil {
		t.Fatal("browser enrollment route unavailable")
	}
	done := make(chan error, 1)
	go func() { _, err := effect(t.Context()); done <- err }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("enrollment ended before reaching the credential update: %v", err)
	}
	lock, err := os.OpenFile(filepath.Join(w.monitor, enrollLockFile), os.O_RDWR, 0)
	if err == nil {
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		lock.Close()
	}
	close(release)
	if !errors.Is(err, unix.EWOULDBLOCK) {
		t.Errorf("another process could enter enrollment concurrently: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := w.command(t.Context(), ownerEnroll, bytes.NewReader(body), &output); err != nil {
		t.Fatalf("SSH enrollment could not reuse the browser's state: %v", err)
	}
}
