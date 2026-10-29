package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"golang.org/x/crypto/ssh"
)

const testInstance = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"

type contractFixture struct {
	OwnerRequest struct {
		Owner    string `json:"owner"`
		Seed     string `json:"seed"`
		Requests []struct {
			Name      string `json:"name"`
			Bytes     string `json:"bytes"`
			InnerBody string `json:"inner_body"`
			Signature string `json:"signature"`
		} `json:"requests"`
		ServerRejects []struct {
			Case      string  `json:"case"`
			Bytes     string  `json:"bytes"`
			Signature string  `json:"signature"`
			Error     *string `json:"error"`
			Server    struct {
				NowMs    int64  `json:"now_ms"`
				Owner    string `json:"owner"`
				Protocol string `json:"protocol"`
				Resource string `json:"resource"`
			} `json:"server"`
		} `json:"server_rejects"`
		InvalidRequests []struct {
			Case  string `json:"case"`
			Bytes string `json:"bytes"`
		} `json:"invalid_requests"`
	} `json:"owner_request"`
	SandboxEHBPKey struct {
		RawHex  string `json:"raw_hex"`
		SPKIHex string `json:"spki_hex"`
	} `json:"sandbox_ehbp_key"`
}

func readFixture(t *testing.T) contractFixture {
	raw, err := os.ReadFile("testdata/owner-contract-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f contractFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func envelope(t *testing.T, raw []byte, signature []byte) []byte {
	out, err := contractJSON(ownerEnvelope{Request: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOwnerContractFixture(t *testing.T) {
	f := readFixture(t).OwnerRequest
	for _, vector := range f.Requests {
		var call ownerRequest
		if err := decodeCanonical([]byte(vector.Bytes), &call); err != nil {
			t.Fatal(err)
		}
		key, err := parseOwnerKey(f.Owner)
		if err != nil {
			t.Fatal(err)
		}
		s := &ownerServer{key: key, instance: call.Resource}
		signature, _ := decodeB64U(vector.Signature, -1)
		got, body, err := s.open(envelope(t, []byte(vector.Bytes), signature), call.IssuedAt)
		if call.Protocol != ownerProtocol {
			if err != errProtocol {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			continue
		}
		if err != nil || got != call || string(body) != vector.InnerBody {
			t.Fatalf("%s: %v %q", vector.Name, err, body)
		}
		if effect, _ := s.route(got, body); effect == nil {
			t.Fatalf("%s: no route", vector.Name)
		}
	}
	checked := 0
	for _, vector := range f.ServerRejects {
		if vector.Server.Protocol != ownerProtocol {
			continue
		}
		checked++
		key, err := parseOwnerKey(vector.Server.Owner)
		if err != nil {
			t.Fatal(err)
		}
		s := &ownerServer{key: key, instance: vector.Server.Resource}
		signature, _ := decodeB64U(vector.Signature, -1)
		_, _, err = s.open(envelope(t, []byte(vector.Bytes), signature), vector.Server.NowMs)
		if (vector.Error == nil) != (err == nil) || (err != nil && err.Error() != *vector.Error) {
			t.Fatalf("%s: got %v", vector.Case, err)
		}
	}
	if checked == 0 {
		t.Fatal("the fixture has no sandbox server vectors")
	}
	seed, _ := decodeB64U(f.Seed, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	key, _ := parseOwnerKey(f.Owner)
	for _, vector := range f.InvalidRequests {
		var call ownerRequest
		json.Unmarshal([]byte(vector.Bytes), &call)
		s := &ownerServer{key: key, instance: call.Resource}
		signature := ed25519.Sign(private, append([]byte(ownerRequestContext), vector.Bytes...))
		if _, _, err := s.open(envelope(t, []byte(vector.Bytes), signature), call.IssuedAt); err != errMalformed {
			t.Fatalf("validly signed %s: %v", vector.Case, err)
		}
	}
}

// TestSandboxEHBPKeyFixture loads the fixture's documented test key the way the CVM
// mounts it and checks that clients would select the same public key.
func TestSandboxEHBPKeyFixture(t *testing.T) {
	f := readFixture(t).SandboxEHBPKey
	seed := sha256.Sum256([]byte("owner-contract-v1/sandbox-ehbp"))
	private, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadEHBPKey(writeKey(t, private))
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(private.PublicKey())
	if hex.EncodeToString(loaded.MarshalPublicKey()) != f.RawHex || hex.EncodeToString(spki) != f.SPKIHex {
		t.Fatalf("loaded %x", loaded.MarshalPublicKey())
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := loadEHBPKey(writeKey(t, ed)); err == nil {
		t.Fatal("loaded an Ed25519 key as the EHBP key")
	}
}

func writeKey(t *testing.T, key any) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private_key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeUnlock stands in for workspace-unlock and the volume worker behind it: a blank
// disk initializes with its first key, and an initialized disk opens only with that key.
const fakeUnlock = `#!/bin/sh
dir=$(dirname "$0")
if [ "$1" = --status ]; then cat "$dir/state"; exit; fi
cat > "$dir/attempt"
echo "$*" >> "$dir/calls"
while [ -e "$dir/hold" ]; do sleep 0.01; done
case $(cat "$dir/state") in
unlocked) exit 0 ;;
locked_blank) [ "$1" = --initialize ] || { echo "volume worker answered b'failed'" >&2; exit 1; }
  cp "$dir/attempt" "$dir/disk" ;;
locked_initialized) cmp -s "$dir/attempt" "$dir/disk" || { echo "volume worker answered b'failed'" >&2; exit 1; } ;;
*) exit 1 ;;
esac
echo unlocked > "$dir/state"
`

type harness struct {
	t        *testing.T
	owner    ed25519.PrivateKey
	public   *identity.Identity
	server   *ownerServer
	url      string
	volume   string
	run      string
	restarts atomic.Int32
	wire     bytes.Buffer // every byte a relay carried
	wireMu   sync.Mutex
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, volume: t.TempDir(), run: filepath.Join(t.TempDir(), "monitor")}
	_, h.owner, _ = ed25519.GenerateKey(rand.Reader)
	ehbpKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sealed, err := loadEHBPKey(writeKey(t, ehbpKey))
	if err != nil {
		t.Fatal(err)
	}
	h.public, _ = identity.FromPublicKeyBytes(ehbpKey.PublicKey().Bytes())
	unlock := filepath.Join(h.volume, "workspace-unlock")
	os.WriteFile(unlock, []byte(fakeUnlock), 0o755)
	h.setVolume("locked_blank")
	h.server = &ownerServer{key: h.owner.Public().(ed25519.PublicKey), instance: testInstance, now: time.Now,
		workspace: &workspace{instance: testInstance, monitor: h.run, uid: os.Getuid(), gid: os.Getgid(), unlock: unlock,
			network: func(context.Context) error { h.restarts.Add(1); return nil }},
		shells: &shells{command: func() *exec.Cmd { return exec.Command("/bin/sh") }, ready: func() error { return nil }}}
	server := httptest.NewServer(routeHandler(attestationClient(filepath.Join(h.volume, "none.sock")), sealedOnly(sealed, h.server)))
	t.Cleanup(server.Close)
	h.url = server.URL + "/owner/rpc"
	return h
}

func (h *harness) setVolume(state string) {
	os.WriteFile(filepath.Join(h.volume, "state"), []byte(state+"\n"), 0o644)
}

func (h *harness) file(name string) string {
	data, _ := os.ReadFile(filepath.Join(h.volume, name))
	return string(data)
}

func id(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// sign signs an owner request at issued with a fresh nonce, as clients retry.
func (h *harness) sign(signer ed25519.PrivateKey, method, path string, body any, operation, session string, issued int64) []byte {
	raw := []byte{}
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	request, err := contractJSON(ownerRequest{Protocol: ownerProtocol, Owner: ownerKeyString(signer.Public().(ed25519.PublicKey)), Resource: testInstance,
		Method: method, Path: path, Body: base64.RawURLEncoding.EncodeToString(raw), Operation: operation, Session: session, IssuedAt: issued, Nonce: id(nonceBytes)})
	if err != nil {
		h.t.Fatal(err)
	}
	return envelope(h.t, request, ed25519.Sign(signer, append([]byte(ownerRequestContext), request...)))
}

// sealed is one EHBP request as a relay forwards it, with the client's response context.
type sealed struct {
	header  http.Header
	body    []byte
	context *identity.RequestContext
}

func (h *harness) seal(envelope []byte) sealed {
	request, _ := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(envelope))
	context, err := h.public.EncryptRequestWithContext(request)
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := io.ReadAll(request.Body)
	return sealed{request.Header, body, context}
}

// send relays sealed bytes and opens the response, recording everything the relay saw.
func (h *harness) send(ctx context.Context, s sealed) (int, []byte, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(s.body))
	request.Header = s.header.Clone()
	request.Header.Del("Transfer-Encoding")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	h.wireMu.Lock()
	h.wire.Write(s.body)
	h.wire.Write(raw)
	h.wireMu.Unlock()
	if err != nil {
		return 0, nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(raw))
	if err := s.context.DecryptResponse(response); err != nil {
		return response.StatusCode, nil, err
	}
	plain, err := io.ReadAll(response.Body)
	return response.StatusCode, plain, err
}

func (h *harness) call(signer ed25519.PrivateKey, method, path string, body any, operation, session string, issued int64) (int, map[string]any) {
	code, plain, err := h.send(context.Background(), h.seal(h.sign(signer, method, path, body, operation, session, issued)))
	if err != nil {
		h.t.Fatal(err)
	}
	var reply map[string]any
	if err := json.Unmarshal(plain, &reply); err != nil {
		h.t.Fatalf("%d %q", code, plain)
	}
	return code, reply
}

func monitorHostKey(t *testing.T) string {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return authorizedKey(key)
}

func TestOwnerAPIRefusesPlaintext(t *testing.T) {
	h := newHarness(t)
	for name, header := range map[string]http.Header{"plaintext": {}, "bodyless sealed": {"Ehbp-Encapsulated-Key": {strings.Repeat("00", 32)}}} {
		body := h.sign(h.owner, http.MethodGet, "/status", nil, id(16), "", time.Now().UnixMilli())
		if name == "bodyless sealed" {
			body = nil
		}
		request, _ := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(body))
		request.Header = header
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		reply, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest || strings.Contains(string(reply), "volume") {
			t.Fatalf("%s: %d %s", name, response.StatusCode, reply)
		}
	}
}

func TestEnrollUnlocksWithOwnerKeyOnly(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UnixMilli()
	code, status := h.call(h.owner, http.MethodGet, "/status", nil, id(16), "", now)
	if code != http.StatusOK || status["volume"] != "locked_blank" || status["agent_public_key"] != nil || status["monitor_host_key"] != nil || status["instance_id"] != testInstance {
		t.Fatalf("initial status: %d %v", code, status)
	}
	agentSeed, diskKey := make([]byte, 32), make([]byte, 32)
	rand.Read(agentSeed)
	rand.Read(diskKey)
	pin := monitorHostKey(t)
	enroll := map[string]any{"agent_seed": base64.RawURLEncoding.EncodeToString(agentSeed), "monitor_host_key": pin,
		"disk_key": base64.RawURLEncoding.EncodeToString(diskKey), "allow_initialize": true}

	// Monitor's host key, the former shell authority, cannot enroll.
	_, monitor, _ := ed25519.GenerateKey(rand.Reader)
	if code, reply := h.call(monitor, http.MethodPost, "/enroll", enroll, id(16), "", now); code != http.StatusUnauthorized || reply["error"] != "invalid_signature" {
		t.Fatalf("Monitor key: %d %v", code, reply)
	}
	if _, err := os.Stat(h.run); !errors.Is(err, os.ErrNotExist) || h.file("calls") != "" {
		t.Fatal("a refused request changed the sandbox")
	}

	operation := id(16)
	code, enrolled := h.call(h.owner, http.MethodPost, "/enroll", enroll, operation, "", now)
	agent, _ := ssh.NewPublicKey(ed25519.NewKeyFromSeed(agentSeed).Public())
	if code != http.StatusOK || enrolled["volume"] != "unlocked" || enrolled["agent_public_key"] != authorizedKey(agent) || enrolled["monitor_host_key"] != pin {
		t.Fatalf("enroll: %d %v", code, enrolled)
	}
	if h.file("attempt") != string(diskKey) || h.file("calls") != "--initialize\n" || h.restarts.Load() != 1 {
		t.Fatalf("unlock got %q with %q after %d restarts", h.file("attempt"), h.file("calls"), h.restarts.Load())
	}
	entries, _ := os.ReadDir(h.run)
	if len(entries) != 2 {
		t.Fatalf("/run/monitor holds %v; only the identity and pin belong there", entries)
	}
	for _, entry := range entries {
		if info, _ := entry.Info(); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", entry.Name(), info.Mode())
		}
	}
	if pinned, _ := os.ReadFile(filepath.Join(h.run, "known_hosts")); string(pinned) != "monitor "+pin+"\n" {
		t.Fatalf("pin %q", pinned)
	}

	// A lost reply: the retry keeps the operation, content and time with a new nonce.
	if code, again := h.call(h.owner, http.MethodPost, "/enroll", enroll, operation, "", now); code != http.StatusOK || again["volume"] != "unlocked" || h.file("calls") != "--initialize\n" {
		t.Fatalf("retry: %d %v %q", code, again, h.file("calls"))
	}
	changed := map[string]any{}
	for k, v := range enroll {
		changed[k] = v
	}
	changed["allow_initialize"] = false
	if code, reply := h.call(h.owner, http.MethodPost, "/enroll", changed, operation, "", now); code != http.StatusConflict || reply["error"] != "operation_conflict" {
		t.Fatalf("changed retry: %d %v", code, reply)
	}
	other := map[string]any{}
	for k, v := range enroll {
		other[k] = v
	}
	other["agent_seed"] = id(32)
	if code, reply := h.call(h.owner, http.MethodPost, "/enroll", other, id(16), "", now); code != http.StatusConflict || reply["error"] != "identity_conflict" {
		t.Fatalf("other identity: %d %v", code, reply)
	}

	// Relinking replaces only the pin of the existing identity.
	identityBefore, _ := os.ReadFile(filepath.Join(h.run, "identity"))
	next := monitorHostKey(t)
	if code, relinked := h.call(h.owner, http.MethodPost, "/relink", map[string]any{"monitor_host_key": next}, id(16), "", now); code != http.StatusOK || relinked["monitor_host_key"] != next || relinked["agent_public_key"] != authorizedKey(agent) {
		t.Fatalf("relink: %d %v", code, relinked)
	}
	identityAfter, _ := os.ReadFile(filepath.Join(h.run, "identity"))
	if !bytes.Equal(identityBefore, identityAfter) || h.restarts.Load() != 2 || h.file("calls") != "--initialize\n" {
		t.Fatal("relink changed the identity or touched storage")
	}

	// Monitor saw only ciphertext.
	for name, secret := range map[string][]byte{"disk key": diskKey, "agent seed": agentSeed, "encoded disk key": []byte(base64.RawURLEncoding.EncodeToString(diskKey)),
		"encoded agent seed": []byte(base64.RawURLEncoding.EncodeToString(agentSeed)), "identity": []byte("OPENSSH PRIVATE KEY"), "status": []byte("unlocked")} {
		if bytes.Contains(h.wire.Bytes(), secret) {
			t.Fatalf("the relay carried the %s in plaintext", name)
		}
	}
}

func TestRelinkAndUsedDiskNeverCreateOrFormat(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UnixMilli()
	if code, reply := h.call(h.owner, http.MethodPost, "/relink", map[string]any{"monitor_host_key": monitorHostKey(t)}, id(16), "", now); code != http.StatusConflict || reply["error"] != "identity_missing" {
		t.Fatalf("relink without identity: %d %v", code, reply)
	}
	if _, err := os.Stat(h.run); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("relink created Monitor credentials")
	}
	existing := []byte("an existing workspace's key")
	os.WriteFile(filepath.Join(h.volume, "disk"), existing, 0o600)
	h.setVolume("locked_initialized")
	enroll := map[string]any{"agent_seed": id(32), "monitor_host_key": monitorHostKey(t), "disk_key": id(32), "allow_initialize": true}
	code, reply := h.call(h.owner, http.MethodPost, "/enroll", enroll, id(16), "", now)
	if code != http.StatusBadGateway || !strings.Contains(reply["error"].(string), "unlock failed") {
		t.Fatalf("wrong key on a used disk: %d %v", code, reply)
	}
	if h.file("disk") != string(existing) || strings.TrimSpace(h.file("state")) != "locked_initialized" {
		t.Fatal("a used disk was reinitialized")
	}
}

// TestAdmittedUnlockSurvivesItsClient: an unlock outlives its connection and deadline,
// concurrent retries share it, and the owner reconciles state afterwards.
func TestAdmittedUnlockSurvivesItsClient(t *testing.T) {
	h := newHarness(t)
	issued := time.Now().UnixMilli()
	os.WriteFile(filepath.Join(h.volume, "hold"), nil, 0o600)
	enroll := map[string]any{"agent_seed": id(32), "monitor_host_key": monitorHostKey(t), "disk_key": id(32), "allow_initialize": true}
	operation := id(16)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, _, err := h.send(ctx, h.seal(h.sign(h.owner, http.MethodPost, "/enroll", enroll, operation, "", issued))); err == nil {
		t.Fatal("the held unlock replied")
	}
	replies := make(chan map[string]any, 2)
	for range 2 {
		go func() {
			_, reply := h.call(h.owner, http.MethodPost, "/enroll", enroll, operation, "", issued)
			replies <- reply
		}()
	}
	time.Sleep(100 * time.Millisecond)
	os.Remove(filepath.Join(h.volume, "hold"))
	for range 2 {
		if reply := <-replies; reply["volume"] != "unlocked" {
			t.Fatalf("retry: %v", reply)
		}
	}
	if h.file("calls") != "--initialize\n" {
		t.Fatalf("unlock ran %q", h.file("calls"))
	}
	// After the deadline the operation is not resubmitted; status reconciles it.
	h.server.now = func() time.Time { return time.UnixMilli(issued + requestWindow + 1) }
	if code, reply := h.call(h.owner, http.MethodPost, "/enroll", enroll, operation, "", issued); code != http.StatusUnauthorized || reply["error"] != "request_expired" {
		t.Fatalf("after the deadline: %d %v", code, reply)
	}
	if _, status := h.call(h.owner, http.MethodGet, "/status", nil, id(16), "", issued+requestWindow+1); status["volume"] != "unlocked" {
		t.Fatalf("status: %v", status)
	}
}

// TestCapturedRequestAfterRestart characterizes the documented limit: a restart loses the
// nonce cache, so a captured request still inside its minute is accepted once more.
func TestCapturedRequestAfterRestart(t *testing.T) {
	h := newHarness(t)
	captured := h.seal(h.sign(h.owner, http.MethodGet, "/status", nil, id(16), "", time.Now().UnixMilli()))
	if code, _, err := h.send(context.Background(), captured); err != nil || code != http.StatusOK {
		t.Fatalf("first: %d %v", code, err)
	}
	code, plain, err := h.send(context.Background(), captured)
	if err != nil || code != http.StatusConflict || !strings.Contains(string(plain), "replayed") {
		t.Fatalf("same boot: %d %s %v", code, plain, err)
	}
	h.server.mu.Lock()
	h.server.nonces, h.server.operations = nil, nil
	h.server.mu.Unlock()
	if code, _, err := h.send(context.Background(), captured); err != nil || code != http.StatusOK {
		t.Fatalf("after restart: %d %v", code, err)
	}
}

func TestNonceExpiryNeverAdmitsAnAcceptedRequest(t *testing.T) {
	const start = 1_800_000_000_000
	now := int64(start)
	s := &ownerServer{now: func() time.Time { return time.UnixMilli(now) }}
	request := func(issued int64) ownerRequest { return ownerRequest{IssuedAt: issued, Nonce: id(nonceBytes)} }
	first := request(start)
	for i := range maxNonces {
		call := request(start)
		if i == 0 {
			call = first
		}
		if err := s.reserve(call); err != nil {
			t.Fatal(err)
		}
	}
	now = start + requestWindow
	if err := s.reserve(first); err != errReplayed {
		t.Fatalf("replay at the inclusive deadline: %v", err)
	}
	if err := s.reserve(request(now)); err != errBusy {
		t.Fatalf("full of live nonces: %v", err)
	}
	now++
	if err := s.reserve(first); err != errExpired {
		t.Fatalf("replay after the deadline: %v", err)
	}
	if err := s.reserve(request(now)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestRequestWindowIsInclusive(t *testing.T) {
	h := newHarness(t)
	const issued = 1_800_000_000_000
	signed := h.sign(h.owner, http.MethodGet, "/status", nil, id(16), "", issued)
	for now, want := range map[int64]error{issued - 1: errFuture, issued: nil, issued + requestWindow: nil, issued + requestWindow + 1: errExpired} {
		if _, _, err := h.server.open(signed, now); err != want {
			t.Fatalf("at %+d ms: %v", now-issued, err)
		}
	}
}

// TestSmallOrderOwnerKeyIsRejected: the identity point verifies R = B, S = 1 for any
// message, so a measured small-order owner key would admit forged requests.
func TestSmallOrderOwnerKeyIsRejected(t *testing.T) {
	weak := edwards25519.NewIdentityPoint().Bytes()
	forged := append(edwards25519.NewGeneratorPoint().Bytes(), make([]byte, 32)...)
	forged[32] = 1
	request, _ := contractJSON(ownerRequest{Protocol: ownerProtocol, Owner: ownerKeyString(weak), Resource: testInstance, Method: http.MethodPost, Path: "/enroll",
		Operation: id(16), IssuedAt: 1_800_000_000_000, Nonce: id(nonceBytes)})
	if _, _, err := (&ownerServer{key: weak, instance: testInstance}).open(envelope(t, request, forged), 1_800_000_000_000); err != nil {
		t.Fatalf("the forgery this guards against no longer verifies: %v", err)
	}
	if _, err := parseOwnerKey(ownerKeyString(weak)); err == nil {
		t.Fatal("accepted the identity point as the measured owner")
	}
	minusOne := append(append([]byte{0xec}, bytes.Repeat([]byte{0xff}, 30)...), 0x7f)
	for _, raw := range [][]byte{minusOne, make([]byte, 32), append(make([]byte, 31), 0x80)} {
		if _, err := parseOwnerKey(ownerKeyString(raw)); err == nil {
			t.Fatalf("accepted small-order key %x", raw)
		}
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := parseOwnerKey(ownerKeyString(public)); err != nil {
		t.Fatal(err)
	}
}
