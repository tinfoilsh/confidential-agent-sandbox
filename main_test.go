package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicHTTPHasNoUnlockOrEnrollment(t *testing.T) {
	box := &sandbox{}
	for _, path := range []string{"/healthz", "/unlock", "/enroll", "/owner/challenge", "/.well-known/tinfoil-attestation"} {
		rec := httptest.NewRecorder()
		box.handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		expected := http.StatusNotFound
		if path == "/healthz" {
			expected = http.StatusNoContent
		}
		if rec.Code != expected {
			t.Fatalf("%s: %d", path, rec.Code)
		}
	}
	for _, path := range []string{"/unlock", "/enroll"} {
		rec := httptest.NewRecorder()
		box.handler().ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(`{"volume":"secret"}`)))
		if rec.Code != http.StatusNotFound {
			t.Fatal("public unlock exposed")
		}
	}
}

func testIdentity(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func testSandbox(t *testing.T) (*sandbox, []byte, func(any) int) {
	t.Helper()
	volume := bytes.Repeat([]byte{7}, volumeKeyBytes)
	box := &sandbox{sshKey: "ecdsa-sha2-nistp256 BOOT", done: func() {}}
	return box, volume, func(body any) int {
		data, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		box.unlockHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/unlock", bytes.NewReader(data)))
		return rec.Code
	}
}

func testVolume(t *testing.T, expected ...[]byte) (unlocked string) {
	t.Helper()
	unlocked, err := os.MkdirTemp("/dev/shm", "volume-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(unlocked) })
	locked := t.TempDir()
	if a, b := testDevice(t, locked), testDevice(t, unlocked); a == b {
		t.Fatal("test needs /dev/shm on another device than the temporary directory")
	}
	previousDisk, previousControl := disk, volumeControl
	disk, volumeControl = filepath.Join(t.TempDir(), "disk"), filepath.Join(t.TempDir(), "control.sock")
	t.Cleanup(func() { disk, volumeControl = previousDisk, previousControl })
	if err := os.Symlink(locked, disk); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: volumeControl, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		connection, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer connection.Close()
		packet := make([]byte, 2+volumeKeyBytes+1)
		n, _ := connection.Read(packet)
		valid := n == 2+volumeKeyBytes
		if len(expected) > 0 {
			valid = n == 2+len(expected[0]) && bytes.Equal(packet[2:n], expected[0])
		}
		if !valid || packet[0] != volumeFormat || packet[1] != opInitialize {
			connection.Write([]byte(statusRejected))
			return
		}
		os.Remove(disk)
		os.Symlink(unlocked, disk)
		connection.Write([]byte(statusOK))
	}()
	return unlocked
}

func testDevice(t *testing.T, path string) uint64 {
	t.Helper()
	dev, err := device(path)
	if err != nil {
		t.Fatal(err)
	}
	return dev
}

func TestUnlockResumesAfterPartialFailureAndRestart(t *testing.T) {
	box, volume, call := testSandbox(t)
	unlocked := testVolume(t, volume)
	identity := testIdentity(t)
	request := func(volume []byte, identity string) int {
		return call(map[string]any{"volume": volume, "monitor_identity": identity})
	}
	wrong := bytes.Clone(volume)
	wrong[0] ^= 1
	blocked := filepath.Join(unlocked, ".monitor.identity")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if code := request(volume, identity); code != http.StatusInternalServerError {
		t.Fatal("failed seal", code)
	}
	if code := request(wrong, identity); code != http.StatusConflict {
		t.Fatal("changed unlock", code)
	}
	os.Remove(blocked)
	if code := request(volume, identity); code != http.StatusNoContent {
		t.Fatal("retry", code)
	}
	saved, err := os.ReadFile(filepath.Join(unlocked, ".monitor.identity"))
	if err != nil || string(saved) != identity {
		t.Fatal("agent identity changed", err)
	}
	if _, err := os.Stat(filepath.Join(unlocked, ".authorized_keys")); !os.IsNotExist(err) {
		t.Fatal("unlock supplied a login key")
	}
	box.enrolled, box.opened = box.sealed(), nil
	if code := request(volume, identity); code != http.StatusNoContent {
		t.Fatal("restart retry", code)
	}
	if code := request(wrong, identity); code != http.StatusConflict {
		t.Fatal("wrong volume retry", code)
	}
	if code := request(volume, testIdentity(t)); code != http.StatusConflict {
		t.Fatal("changed identity retry", code)
	}
	box.sshKey, box.opened = "ecdsa-sha2-nistp256 NEXT", nil
	if box.enrolled = box.sealed(); box.enrolled {
		t.Fatal("old boot receipt accepted")
	}
	if code := request(volume, identity); code == http.StatusNoContent {
		t.Fatal("old boot unlock acknowledged")
	}
}

func TestUnlockRejectsLoginKeysRoutesAndInvalidSecrets(t *testing.T) {
	box, volume, call := testSandbox(t)
	identity := testIdentity(t)
	for _, body := range []map[string]any{
		{"volume": volume, "monitor_identity": identity, "key": "ssh-ed25519 ATTACKER"},
		{"volume": volume, "monitor_identity": identity, "monitor": map[string]string{"ip": "198.51.100.7"}},
		{"volume": volume[:31], "monitor_identity": identity},
		{"volume": "invalid base64", "monitor_identity": identity},
		{"volume": volume, "monitor_identity": "invalid key"},
	} {
		if code := call(body); code != http.StatusBadRequest || box.opened != nil {
			t.Fatal("invalid request reached volume", code)
		}
	}
}

func TestMeasuredOwnerKeyIsTheSSHLoginKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := "ed25519:" + base64.StdEncoding.EncodeToString(public)
	line, err := ownerSSHKey(binding)
	if err != nil {
		t.Fatal(err)
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	expected, _ := ssh.NewPublicKey(public)
	if err != nil || !bytes.Equal(key.Marshal(), expected.Marshal()) || len(options) != 0 || len(rest) != 0 {
		t.Fatal("SSH owner binding changed")
	}
	for _, invalid := range []string{"", "invalid", binding + "\n"} {
		t.Setenv("SANDBOX_OWNER_PUBLIC_KEY", invalid)
		if err := run(); err == nil || !strings.Contains(err.Error(), "SANDBOX_OWNER_PUBLIC_KEY") {
			t.Fatal("invalid binding accepted", err)
		}
	}
}

func TestSSHHelperUnlocksThroughPrivateSocket(t *testing.T) {
	box, volume, _ := testSandbox(t)
	testVolume(t, volume)
	old := unlockSocket
	unlockSocket = filepath.Join(t.TempDir(), "unlock.sock")
	defer func() { unlockSocket = old }()
	listener, err := net.Listen("unix", unlockSocket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: box.unlockHandler()}
	go server.Serve(listener)
	defer server.Close()
	body, _ := json.Marshal(map[string]any{"volume": volume, "monitor_identity": testIdentity(t)})
	if err := forwardUnlock(bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if err := forwardUnlock(bytes.NewReader(body)); err != nil {
		t.Fatal("retry", err)
	}
	if err := forwardUnlock(strings.NewReader(`{"key":"supplied-login-key"}`)); err == nil {
		t.Fatal("accepted enrollment login key")
	}
}
