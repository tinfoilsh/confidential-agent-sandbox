// Command confidential-agent-sandbox is the API served inside a sandbox CVM that
// orchestrator creates. It is the guest half of one contract: orchestrator
// mints a short-lived ES256 permit naming a sandbox's domain and the nonce of
// the boot it is meant for, and that permit buys exactly one thing -- the right
// to name the public key that owns this sandbox for the rest of the boot.
//
// The permit is spent by the call that uses it. After one POST /enroll succeeds
// the orchestrator's key is never read again, so the party that launched the
// sandbox cannot re-enter it: the workspace answers only to signatures from the
// key that call enrolled. Before that call it answers to nobody at all.
//
// Both halves of every check are local. The orchestrator's key is pinned in the
// measured config, so a client attesting this enclave is told who may introduce
// an owner; the nonce is minted here at startup, so neither a permit nor an
// enrollment outlives the boot it was made against. Verification therefore needs
// no network and no stored state, and nothing here ever dials out.
//
// The enrolled key is also the sandbox's SSH credential. Enrollment seals it
// into the one authorized_keys sshd will ever read and starts sshd, which is
// configured for publickey and nothing else: no password, no keyboard-interactive,
// no host-based, no second key, and no listener at all until an owner exists.
// One key opens both doors, so the shell is reachable by exactly the party the
// permit named and the measurement can say so without describing a second
// credential.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// listen is shim.upstream-port in tinfoil-config.yml. The shim terminates
	// TLS on 443 with the CVM's attested certificate and is the only way in, so
	// this listener is enclave-internal and plaintext by design.
	listen = ":8080"

	// workspace is a tmpfs declared in the measured config. What an owner writes
	// lives in enclave memory and goes when the boot does, which is the same
	// lifetime its enrollment has.
	workspace = "/workspace"

	maxFileBytes = 1 << 20

	// An enrollment carries one P-256 SPKI DER key in base64, which is under
	// 200 bytes of JSON. The limit is what keeps an unauthenticated body from
	// being interesting.
	maxEnrollBytes = 1 << 10

	coordinate = 32 // bytes per ECDSA P-256 signature half, as JWS packs them

	// sshPort is where sshd listens inside the container. tinfoil-config
	// publishes it as the CVM's port 22, which is the only reason the measured
	// firewall has a forward path to it.
	sshPort = 22

	// sshRun is a tmpfs declared in the measured config, holding everything sshd
	// reads: a host key minted at boot, the config rendered from the constant
	// below, and the one authorized_keys an enrollment seals. The rootfs under it
	// is read-only, the directory is root-owned, and an SSH session runs as
	// sandboxUser -- so a session can read what sshd trusts and change none of it.
	sshRun     = "/run/sshd"
	hostKey    = sshRun + "/host_key"
	sshdConfig = sshRun + "/sshd_config"
	authorized = sshRun + "/authorized_keys"

	sshd = "/usr/sbin/sshd"

	// The login account, created in the image with /workspace as its home. It is
	// not the account this program runs as: an owner's shell cannot reach the
	// sealed credential, the host key, or this process.
	sandboxUser = "sandbox"

	// sshKeyType is the only key an enrollment can name, because publicKey
	// accepts nothing but P-256 -- so the SSH credential and the JWS credential
	// are necessarily the same key.
	sshKeyType  = "ecdsa-sha2-nistp256"
	sshKeyCurve = "nistp256"
)

// sshdPolicy is sshd's whole configuration: publickey against one sealed file,
// and every other way in named and refused rather than left to a default. It is
// rendered to sshRun at boot and checked with `sshd -t` there, because after an
// enrollment there is no second chance to get it right. PAM and GSSAPI are
// absent rather than disabled -- the image's sshd is built without either, and
// `sshd -t` would only warn about naming them -- which AuthenticationMethods
// makes moot in any case.
const sshdPolicy = `Port %d
HostKey %s
AuthorizedKeysFile %s
PidFile none

AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
AllowUsers %s
StrictModes yes

AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
X11Forwarding no

LoginGraceTime 30
MaxAuthTries 3
MaxSessions 8
MaxStartups 4:50:8
ClientAliveInterval 60
ClientAliveCountMax 3
PrintMotd no

# Every accepted key is logged with its fingerprint, which is the only record
# this boot keeps of who came in and dies with it.
LogLevel VERBOSE

# scp and sftp are how an owner moves files over the door they already have;
# internal-sftp needs no binary on the read-only rootfs.
Subsystem sftp internal-sftp
`

type sandbox struct {
	domain string
	issuer string
	permit *ecdsa.PublicKey
	nonce  string
	files  *os.Root

	// fingerprint identifies the host key sshd will present, minted at boot and
	// reported by /healthz. A client reads it over the attested channel before it
	// ever dials port 22, so the shell needs no trust-on-first-use.
	fingerprint string

	// owner is the key named by the one permit this boot honours, and nil until
	// then. That single field is the whole of the authorization state: with no
	// owner the workspace serves nobody, and with one the orchestrator's key has
	// no further use. listening follows it: sshd is started by the enrollment
	// that seals the key, so before one there is no SSH listener to attack.
	mu        sync.Mutex
	owner     *ecdsa.PublicKey
	listening bool
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// DOMAIN is the only value that differs per sandbox, so it arrives through
	// the unmeasured external config tinfoild writes at launch -- the same entry
	// tinfoil-boot reads to get the certificate. A permit's subject is checked
	// against it, so the measurement covers that the check happens and the
	// launch decides which name it happens for.
	box := &sandbox{
		domain: os.Getenv("DOMAIN"),
		issuer: os.Getenv("SANDBOX_PERMIT_ISSUER"),
		// Every credential this boot honours is bound to this string. Minting
		// it here rather than accepting one from the host is what ties them to
		// a boot: the host can only learn the nonce of the instance actually
		// running, so it cannot carry authority across a restart, and a reboot
		// discards the enrollment along with the workspace it protected.
		nonce: rand.Text(),
	}
	if box.domain == "" {
		return errors.New("DOMAIN is not set")
	}
	if box.issuer == "" {
		return errors.New("SANDBOX_PERMIT_ISSUER is not set")
	}
	permit, err := publicKey(os.Getenv("SANDBOX_PERMIT_KEY"))
	if err != nil {
		return fmt.Errorf("SANDBOX_PERMIT_KEY: %w", err)
	}
	box.permit = permit

	// Every file operation goes through a root confined to the workspace mount,
	// so a path leaving it is an error the kernel returns rather than one this
	// program has to be careful enough to prevent. Symlinks included.
	files, err := os.OpenRoot(workspace)
	if err != nil {
		return err
	}
	defer files.Close()
	box.files = files

	// Everything sshd needs except a key to accept. Failing here is a refusal to
	// boot, which is the only place a broken SSH policy can still be refused:
	// once an enrollment has been claimed it cannot be handed back.
	if err := box.prepare(); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := &http.Server{
		Addr:              listen,
		Handler:           box.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Printf("shutdown failed: %v", err)
		}
	}()

	log.Printf("sandbox %s serving boot %s, awaiting enrollment", box.domain, box.nonce)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// handler serves the exact paths the shim's allowlist names, so the workspace
// is one path under three verbs rather than a family of them.
func (s *sandbox) handler() http.Handler {
	mux := http.NewServeMux()
	// Open by necessity: a permit is bound to this nonce, so orchestrator has
	// to read the nonce before a permit can exist. It is an identifier, not a
	// secret -- holding it grants nothing without the orchestrator's key.
	mux.HandleFunc("GET /healthz", s.health)
	// The one call a permit authorizes, and the only one it ever will.
	mux.HandleFunc("POST /enroll", s.enroll)
	mux.HandleFunc("GET /workspace", s.gate(s.read))
	mux.HandleFunc("POST /workspace", s.gate(s.write))
	mux.HandleFunc("DELETE /workspace", s.gate(s.remove))
	return mux
}

// health reports the facts a caller needs before it can hold any credential
// here: the nonce a permit must be bound to, whether this boot's permit has
// already been spent, and the host key the shell will present. None is a secret,
// and an owner who finds a boot it did not enroll knows to stop talking to it.
func (s *sandbox) health(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	enrolled, listening := s.owner != nil, s.listening
	s.mu.Unlock()
	reply(w, http.StatusOK, map[string]any{
		"domain":   s.domain,
		"nonce":    s.nonce,
		"enrolled": enrolled,
		"ssh": map[string]any{
			"port":      sshPort,
			"user":      sandboxUser,
			"host-key":  s.fingerprint,
			"listening": listening,
		},
	})
}

// enroll spends this boot's permit on naming an owner. The permit is verified
// before the body is read, so an unauthenticated caller learns nothing; the
// claim is then what makes it single-use, because it refuses a sandbox that
// already has an owner and no permit is ever read after one does.
func (s *sandbox) enroll(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		reply(w, http.StatusUnauthorized, failure{"missing permit"})
		return
	}
	if err := s.check(token, s.permit); err != nil {
		log.Printf("permit refused: %v", err)
		reply(w, http.StatusForbidden, failure{"permit refused"})
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrollBytes)).Decode(&body); err != nil {
		reply(w, http.StatusBadRequest, failure{"enrollment is not a JSON object naming a key"})
		return
	}
	owner, err := publicKey(body.Key)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"key is not base64 SPKI DER for a P-256 public key"})
		return
	}
	// Rendered before the claim, so a key that could not be an SSH credential
	// does not get to spend the permit: both doors are opened by one call or
	// neither is.
	line, err := authorizedKey(owner)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"key cannot be used as an SSH credential"})
		return
	}
	if err := s.claim(owner); err != nil {
		// The permit verified, so this is a valid permit arriving after the one
		// that spent it: a replay, or a second holder of the same permit.
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusConflict, failure{"sandbox is already enrolled"})
		return
	}
	// The workspace is already this owner's, so a door that failed to open is
	// reported rather than refused -- /healthz says whether sshd is listening.
	if err := s.seal(line); err != nil {
		log.Printf("ssh seal failed: %v", err)
	}
	log.Printf("sandbox %s enrolled an owner for boot %s", s.domain, s.nonce)
	w.WriteHeader(http.StatusNoContent)
}

// prepare mints the host key and renders sshd's configuration. The host key is
// generated here rather than baked into the image so it is as short-lived as the
// boot and as unique as the nonce: a sandbox cannot be impersonated by a party
// holding the image. `sshd -t` then parses what was written, so the policy this
// program depends on is known good before any of it matters.
func (s *sandbox) prepare() error {
	if err := command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", hostKey); err != nil {
		return fmt.Errorf("host key: %w", err)
	}
	policy := fmt.Sprintf(sshdPolicy, sshPort, hostKey, authorized, sandboxUser)
	// Readable so sshd can read it after dropping to the login account, and
	// writable by nobody: the directory is root-owned on a read-only rootfs.
	if err := os.WriteFile(sshdConfig, []byte(policy), 0o444); err != nil {
		return err
	}
	if err := command(sshd, "-t", "-f", sshdConfig); err != nil {
		return fmt.Errorf("policy is not one sshd accepts: %w", err)
	}
	fingerprint, err := digest(hostKey + ".pub")
	if err != nil {
		return err
	}
	s.fingerprint = fingerprint
	log.Printf("ssh host key %s ready on port %d", fingerprint, sshPort)
	return nil
}

// seal writes the one credential sshd will ever accept and starts it. The file
// is created O_EXCL and read-only, so the single call that reaches here cannot
// be joined by a second: an owner's own session cannot add a key, and no later
// enrollment exists to try.
func (s *sandbox) seal(line string) error {
	file, err := os.OpenFile(authorized, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(line); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// -e keeps sshd's log in the enclave's console alongside this program's,
	// which is the only place either is readable.
	daemon := exec.Command(sshd, "-D", "-e", "-f", sshdConfig)
	daemon.Stdout, daemon.Stderr = os.Stderr, os.Stderr
	if err := daemon.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.listening = true
	s.mu.Unlock()
	go func() {
		err := daemon.Wait()
		s.mu.Lock()
		s.listening = false
		s.mu.Unlock()
		// Nothing restarts it: the sealed key is spent, so a sandbox that loses
		// sshd keeps serving the workspace over the door that still works.
		log.Printf("sshd exited: %v", err)
	}()
	log.Printf("ssh sealed to the enrolled key, listening on port %d as %s", sshPort, sandboxUser)
	return nil
}

// authorizedKey renders the owner's P-256 key as an authorized_keys line. The
// SSH credential is the enrollment key itself -- the same key that signs every
// /workspace call -- so the second door introduces no second secret and no third
// party. The wire format is three length-prefixed strings, which is the whole
// reason this program still has no dependencies to audit.
func authorizedKey(key *ecdsa.PublicKey) (string, error) {
	point, err := key.Bytes()
	if err != nil {
		return "", err
	}
	var blob []byte
	for _, field := range [][]byte{[]byte(sshKeyType), []byte(sshKeyCurve), point} {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(field)))
		blob = append(blob, field...)
	}
	return sshKeyType + " " + base64.StdEncoding.EncodeToString(blob) + "\n", nil
}

// digest is the SHA256 fingerprint of a public key file, in the form ssh-keygen
// prints and a client compares against.
func digest(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(content))
	if len(fields) < 2 {
		return "", fmt.Errorf("%s is not a public key", path)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// command runs one of OpenSSH's own tools and keeps its complaint in the error,
// since a failure here is a boot that should not continue.
func command(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// claim names the owner, once. Every later caller is refused -- including the
// holder of the permit that won, which is what stops a permit being replayed.
func (s *sandbox) claim(owner *ecdsa.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != nil {
		return errors.New("an owner is already enrolled for this boot")
	}
	s.owner = owner
	return nil
}

func (s *sandbox) ownerKey() *ecdsa.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owner
}

// gate admits the enrolled owner and nobody else. The orchestrator's key is not
// consulted here at all, so whoever launched this sandbox introduced its owner
// once and has no way back in.
func (s *sandbox) gate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		owner := s.ownerKey()
		if owner == nil {
			reply(w, http.StatusUnauthorized, failure{"sandbox has no enrolled owner"})
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			reply(w, http.StatusUnauthorized, failure{"missing token"})
			return
		}
		if err := s.check(token, owner); err != nil {
			// Which check failed describes the token the caller already holds,
			// so it is logged inside the enclave and not answered with.
			log.Printf("token refused: %v", err)
			reply(w, http.StatusForbidden, failure{"token refused"})
			return
		}
		next(w, r)
	}
}

// check verifies one JWS against one key: ES256 over the signing input, then the
// claims that tie it to this boot of this sandbox. Orchestrator's permit and the
// owner's own tokens are the same shape, so enrolling changes which key is
// trusted and nothing else. The signature is checked first, so no claim is ever
// read from an unsigned token.
func (s *sandbox) check(token string, key *ecdsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("token is not a JWS")
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	if err := decode(parts[0], &header); err != nil {
		return fmt.Errorf("token header: %w", err)
	}
	if header.Algorithm != "ES256" {
		return fmt.Errorf("token algorithm is %q, not ES256", header.Algorithm)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("token signature: %w", err)
	}
	if len(signature) != 2*coordinate {
		return fmt.Errorf("token signature is %d bytes, want %d", len(signature), 2*coordinate)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key,
		digest[:],
		new(big.Int).SetBytes(signature[:coordinate]),
		new(big.Int).SetBytes(signature[coordinate:]),
	) {
		return errors.New("signature does not match the key this check trusts")
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		Expires  int64           `json:"exp"`
	}
	if err := decode(parts[1], &claims); err != nil {
		return fmt.Errorf("token claims: %w", err)
	}
	switch {
	case claims.Issuer != s.issuer:
		return fmt.Errorf("token issuer is %q, not %q", claims.Issuer, s.issuer)
	case claims.Subject != s.domain:
		return fmt.Errorf("token names %q, not this sandbox", claims.Subject)
	case claims.Expires == 0:
		return errors.New("token does not expire")
	case time.Now().After(time.Unix(claims.Expires, 0)):
		return errors.New("token has expired")
	case !slices.Contains(audiences(claims.Audience), s.nonce):
		return errors.New("token is bound to another boot")
	}
	return nil
}

// read answers a named file, or every file in the workspace when no name is
// given, since a workspace nobody can enumerate is one you must remember by
// heart. The walk is recursive because a write may have nested.
func (s *sandbox) read(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("path")
	if name == "" {
		names := []string{}
		if err := fs.WalkDir(s.files.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
			if err == nil && !entry.IsDir() {
				names = append(names, path)
			}
			return err
		}); err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, names)
		return
	}
	content, err := s.files.ReadFile(name)
	if err != nil {
		refuse(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(content); err != nil {
		log.Printf("response failed: %v", err)
	}
}

func (s *sandbox) write(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("path")
	content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFileBytes))
	if err != nil {
		reply(w, http.StatusBadRequest, failure{"file is unreadable or larger than the workspace allows"})
		return
	}
	if err := s.files.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		refuse(w, err)
		return
	}
	if err := s.files.WriteFile(name, content, 0o600); err != nil {
		refuse(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *sandbox) remove(w http.ResponseWriter, r *http.Request) {
	if err := s.files.Remove(r.URL.Query().Get("path")); err != nil {
		refuse(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// refuse answers a file operation the workspace would not perform. A path that
// left the root, named a directory, or was never there is the caller's mistake;
// which of those it was stays in the enclave log.
func refuse(w http.ResponseWriter, err error) {
	log.Printf("workspace refused: %v", err)
	if errors.Is(err, fs.ErrNotExist) {
		reply(w, http.StatusNotFound, failure{"no such file"})
		return
	}
	reply(w, http.StatusBadRequest, failure{"path is not usable"})
}

// publicKey reads a P-256 verifying key as base64 SPKI DER. Both keys this
// program trusts arrive that way: the orchestrator's from the measured config,
// so the document a client attests names who may introduce an owner, and the
// owner's from the enrollment call that named it.
func publicKey(encoded string) (*ecdsa.PublicKey, error) {
	if encoded == "" {
		return nil, errors.New("no key given")
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("key is not P-256")
	}
	return key, nil
}

// audiences reads aud either way a JWT may carry it: one string, or a list.
func audiences(raw json.RawMessage) []string {
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	return nil
}

func decode(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

type failure struct {
	Error string `json:"error"`
}

func fail(w http.ResponseWriter, err error) {
	log.Printf("request failed: %v", err)
	reply(w, http.StatusInternalServerError, failure{"internal error"})
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("response failed: %v", err)
	}
}
