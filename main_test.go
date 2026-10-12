package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollmentHandlerLeavesAttestationToShim(t *testing.T) {
	box := &sandbox{}
	for _, path := range []string{"/healthz", "/.well-known/tinfoil-attestation", "/.well-known/tinfoil-certificate", "/bootstrap"} {
		rec := httptest.NewRecorder()
		box.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if path == "/healthz" {
			if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
				t.Fatalf("readiness response: %d %s", rec.Code, rec.Body.String())
			}
		} else if rec.Code != http.StatusNotFound {
			t.Fatalf("unexpected endpoint %s: %d", path, rec.Code)
		}
	}
}

// A sandbox on its Monitor's host reaches Monitor at the bridge gateway.
var testRoute = monitorRoute{Domain: "personal.example", IP: "100.64.0.1", Port: 18293, HostKey: "ssh-ed25519 AAAA"}

// testSandbox binds a workspace key before serving enrollment requests.
func testSandbox(t *testing.T) (*sandbox, []byte, func(path string, body any) int) {
	t.Helper()
	volume := make([]byte, volumeKeyBytes)
	if _, err := rand.Read(volume); err != nil {
		t.Fatal(err)
	}
	ownerHash := sha256.Sum256(volume)
	box := &sandbox{domain: "work.example", owner: &ownerCommitment{hash: ownerHash[:]}, sshKey: "ecdsa-sha2-nistp256 BOOT", done: func() {}}
	return box, volume, func(path string, body any) int {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
		rec := httptest.NewRecorder()
		box.handler().ServeHTTP(rec, req)
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
		packet := make([]byte, 2+maxVolumeKeyBytes+1)
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

func TestEnrollmentResumesAfterTheUnlockAndRestart(t *testing.T) {
	box, volume, call := testSandbox(t)
	unlocked := testVolume(t)
	login := func() string {
		blob := binary.BigEndian.AppendUint32(nil, 11)
		blob = append(blob, "ssh-ed25519"...)
		blob = binary.BigEndian.AppendUint32(blob, 32)
		key := make([]byte, 32)
		rand.Read(key)
		return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(blob, key...))
	}
	key, route := login(), testRoute
	route.Identity = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
	enroll := func(key string, volume []byte, route monitorRoute) int {
		return call("/enroll", map[string]any{"key": key, "volume": base64.StdEncoding.EncodeToString(volume), "monitor": route})
	}
	wrongVolume := bytes.Clone(volume)
	wrongVolume[0] ^= 1

	// Even a fresh disk must reject a key other than the boot-bound owner's.
	if code := enroll(key, wrongVolume, route); code != http.StatusForbidden {
		t.Fatalf("wrong owner key before enrollment: %d", code)
	}
	if box.opened != nil || box.enrolled {
		t.Fatal("wrong owner key changed enrollment state")
	}

	// The disk refuses the login key after the volume worker has spent its one unlock.
	blocked := filepath.Join(unlocked, ".authorized_keys")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if code := enroll(key, volume, route); code != http.StatusInternalServerError {
		t.Fatalf("enrollment with a failing disk: %d", code)
	}
	if code := enroll(key, wrongVolume, route); code != http.StatusForbidden {
		t.Fatalf("another workspace key after the unlock: %d", code)
	}
	os.Remove(blocked)
	if code := enroll(key, volume, route); code != http.StatusNoContent {
		t.Fatalf("identical retry after the unlock: %d", code)
	}
	if login, _ := os.ReadFile(filepath.Join(unlocked, ".authorized_keys")); !bytes.Contains(login, []byte(key)) {
		t.Fatalf("sealed login key %q", login)
	}
	var sealed monitorRoute
	if data, _ := os.ReadFile(filepath.Join(unlocked, ".monitor.json")); json.Unmarshal(data, &sealed) != nil || sealed != route {
		t.Fatalf("sealed Monitor configuration %+v", sealed)
	}

	// An in-sandbox reboot restarts the service using the receipt on the open disk.
	box.enrolled, box.opened = box.sealed(), nil
	if code := enroll(key, volume, route); code != http.StatusNoContent {
		t.Fatalf("identical retry after restart: %d", code)
	}
	otherIdentity := route
	otherIdentity.Identity = "-----BEGIN OPENSSH PRIVATE KEY-----\nBBBB\n-----END OPENSSH PRIVATE KEY-----\n"
	otherEndpoint := route
	otherEndpoint.Port++
	if code := enroll(key, wrongVolume, route); code != http.StatusForbidden {
		t.Fatalf("wrong owner after restart: %d", code)
	}
	for name, code := range map[string]int{
		"agent identity":   enroll(key, volume, otherIdentity),
		"Monitor endpoint": enroll(key, volume, otherEndpoint),
		"login key":        enroll(login(), volume, route),
	} {
		if code != http.StatusConflict {
			t.Errorf("%s after restart: %d", name, code)
		}
	}

	// The next boot crashed after opening the same disk, so only an earlier receipt is on it.
	box.sshKey, box.opened = "ecdsa-sha2-nistp256 NEXT", nil
	if box.enrolled = box.sealed(); box.enrolled {
		t.Fatal("an earlier boot's receipt counts as this boot's enrollment")
	}
	if code := enroll(key, volume, route); code == http.StatusNoContent {
		t.Fatal("acknowledged an earlier boot's enrollment")
	}
}

func TestUncontainedEnrollmentHasNoMonitor(t *testing.T) {
	_, volume, call := testSandbox(t)
	unlocked := testVolume(t)
	body := map[string]any{"key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", "volume": base64.StdEncoding.EncodeToString(volume)}
	// An earlier contained boot left its Monitor on the disk.
	if err := os.WriteFile(filepath.Join(unlocked, ".monitor.json"), []byte(`{"ip":"198.51.100.9"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if code := call("/enroll", body); code != http.StatusNoContent {
		t.Fatalf("enrollment without a Monitor: %d", code)
	}
	if data, _ := os.ReadFile(filepath.Join(unlocked, ".monitor.json")); string(data) != "null" {
		t.Fatalf("sealed Monitor configuration holds %q", data)
	}

	if code := call("/enroll", body); code != http.StatusNoContent {
		t.Fatalf("identical retry: %d", code)
	}
	route := testRoute
	route.Identity = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
	body["monitor"] = route
	if code := call("/enroll", body); code != http.StatusConflict {
		t.Fatalf("retry adding a Monitor: %d", code)
	}
}

func TestEnrollmentRequiresBootOwnerConfiguration(t *testing.T) {
	t.Setenv("DOMAIN", "work.example")
	t.Setenv("SANDBOX_OWNER_KEY_ARGON2ID", "")
	for _, value := range []string{"not-hex", "aa"} {
		t.Setenv("SANDBOX_OWNER_KEY_SHA256", value)
		if err := run(); err == nil || err.Error() != "SANDBOX_OWNER_KEY_SHA256 must be a SHA-256 digest in hex" {
			t.Fatalf("invalid owner config %q: %v", value, err)
		}
	}
	box, volume, call := testSandbox(t)
	box.owner = nil
	if code := call("/enroll", map[string]string{"volume": base64.StdEncoding.EncodeToString(volume)}); code != http.StatusForbidden {
		t.Fatalf("missing boot owner accepted enrollment: %d", code)
	}
}
