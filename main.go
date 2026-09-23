// Command workspace-enroll serves the permit-gated enrollment API until the
// volume is open.
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
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	listen = ":8080"

	disk = "/mnt/disk"

	// Left on the disk the enrollment opened, so a restart inside a live CVM stages it without a second enrollment.
	authorized = disk + "/.authorized_keys"

	hostKey = "/run/workspace/host_key"

	volumeControl  = "/run/tinfoil/volumes/workspace/control.sock"
	volumeKeyBytes = 64
	volumeTimeout  = 10 * time.Second
	// A first unlock formats the volume, which takes minutes on a large one.
	volumeFormatTimeout = 15 * time.Minute

	opUnlock     = "unlock"
	opInitialize = "initialize"

	statusOK       = "ok"
	statusRejected = "rejected"

	maxStatusBytes = 1 << 8
	maxEnrollBytes = 1 << 12

	coordinate = 32

	certificateSuffix = "-cert-v01@openssh.com"

	sshPort   = 22
	loginUser = "sandbox"
)

type sandbox struct {
	domain      string
	issuer      string
	permit      *ecdsa.PublicKey
	nonce       string
	fingerprint string

	done context.CancelFunc

	mu       sync.Mutex
	enrolled bool

	enrolling sync.Mutex
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	box := &sandbox{
		domain: os.Getenv("DOMAIN"),
		issuer: os.Getenv("SANDBOX_PERMIT_ISSUER"),
		nonce:  rand.Text(),
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
	if box.fingerprint, err = digest(hostKey + ".pub"); err != nil {
		return fmt.Errorf("ssh host key: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	box.done = stop

	server := &http.Server{
		Addr:              listen,
		Handler:           box.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	served := make(chan error, 1)
	go func() { served <- server.ListenAndServe() }()
	log.Printf("workspace %s serving boot %s, awaiting enrollment", box.domain, box.nonce)
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}

func (s *sandbox) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /enroll", s.enroll)
	return mux
}

func (s *sandbox) health(w http.ResponseWriter, r *http.Request) {
	reply(w, http.StatusOK, map[string]any{
		"domain":   s.domain,
		"nonce":    s.nonce,
		"enrolled": s.isEnrolled(),
		"ssh": map[string]any{
			"port":     sshPort,
			"user":     loginUser,
			"host-key": s.fingerprint,
		},
	})
}

// The volume is opened before the owner is claimed, so a refused volume key leaves the permit unspent.
func (s *sandbox) enroll(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		reply(w, http.StatusUnauthorized, failure{"missing permit"})
		return
	}
	if err := s.check(token); err != nil {
		log.Printf("permit refused: %v", err)
		reply(w, http.StatusForbidden, failure{"permit refused"})
		return
	}
	var body struct {
		Key    string `json:"key"`
		Volume string `json:"volume"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrollBytes)).Decode(&body); err != nil {
		reply(w, http.StatusBadRequest, failure{"enrollment is not a JSON object naming a key"})
		return
	}
	volumeKey, err := workspaceKey(body.Volume)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"volume is not base64 for a 64-byte workspace key"})
		return
	}
	defer clear(volumeKey)
	line, err := authorizedKey(body.Key)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"key is not one SSH public key"})
		return
	}
	s.enrolling.Lock()
	defer s.enrolling.Unlock()
	if s.isEnrolled() {
		log.Printf("enrollment refused: an owner is already enrolled for this boot")
		reply(w, http.StatusConflict, failure{"sandbox is already enrolled"})
		return
	}
	if err := open(volumeKey); err != nil {
		log.Printf("workspace refused the key: %v", err)
		reply(w, http.StatusForbidden, failure{"workspace key refused"})
		return
	}
	if err := seal(line); err != nil {
		log.Printf("workspace provisioning failed: %v", err)
		reply(w, http.StatusInternalServerError, failure{"workspace could not be provisioned"})
		return
	}
	s.mu.Lock()
	s.enrolled = true
	s.mu.Unlock()
	log.Printf("workspace %s enrolled an owner for boot %s", s.domain, s.nonce)
	w.WriteHeader(http.StatusNoContent)
	s.done()
}

func (s *sandbox) isEnrolled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enrolled
}

func workspaceKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(key) != volumeKeyBytes {
		clear(key)
		return nil, fmt.Errorf("workspace key is %d bytes, want %d", len(key), volumeKeyBytes)
	}
	return key, nil
}

// disk is a mount before any volume is behind it, so only the device changing proves the unlock.
func open(key []byte) error {
	locked, err := device(disk)
	if err != nil {
		return err
	}
	if err := unlock(key); err != nil {
		return err
	}
	unlocked, err := device(disk)
	if err != nil {
		return err
	}
	if unlocked == locked {
		return errors.New("volume worker reported success without mounting the workspace")
	}
	return nil
}

func unlock(key []byte) error {
	status, err := control(opInitialize, key)
	if err != nil {
		return err
	}
	if status == statusRejected {
		if status, err = control(opUnlock, key); err != nil {
			return err
		}
	}
	if status != statusOK {
		return fmt.Errorf("volume worker answered %q", status)
	}
	return nil
}

// No read deadline: a first unlock formats the volume, which takes minutes on a large disk.
func control(operation string, key []byte) (string, error) {
	packet, err := json.Marshal(request{Op: operation, Key: key})
	if err != nil {
		return "", err
	}
	defer clear(packet)
	connection, err := net.Dial("unixpacket", volumeControl)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if err := connection.SetWriteDeadline(time.Now().Add(volumeTimeout)); err != nil {
		return "", err
	}
	if _, err := connection.Write(packet); err != nil {
		return "", err
	}
	if err := connection.SetReadDeadline(time.Now().Add(volumeFormatTimeout)); err != nil {
		return "", err
	}
	var reply [maxStatusBytes]byte
	n, err := connection.Read(reply[:])
	if err != nil {
		return "", err
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(reply[:n], &status); err != nil {
		return "", err
	}
	return status.Status, nil
}

type request struct {
	Op  string `json:"op"`
	Key []byte `json:"key"`
}

func device(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Sys().(*syscall.Stat_t).Dev, nil
}

func seal(line string) error {
	if err := os.WriteFile(authorized, []byte(line), 0o644); err != nil {
		return err
	}
	syscall.Sync()
	return nil
}

func authorizedKey(line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", errors.New("line is not a type and a key")
	}
	if strings.HasSuffix(fields[0], certificateSuffix) {
		return "", errors.New("line names a certificate, not a key")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", err
	}
	if len(blob) < 4 || len(blob) < 4+int(binary.BigEndian.Uint32(blob)) {
		return "", errors.New("key is not an SSH public key blob")
	}
	if named := string(blob[4 : 4+binary.BigEndian.Uint32(blob)]); named != fields[0] {
		return "", fmt.Errorf("key is a %s, not the %s the line names", named, fields[0])
	}
	return fields[0] + " " + fields[1] + "\n", nil
}

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

func (s *sandbox) check(token string) error {
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
	if !ecdsa.Verify(s.permit,
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
		return fmt.Errorf("token names %q, not this workspace", claims.Subject)
	case claims.Expires == 0:
		return errors.New("token does not expire")
	case time.Now().After(time.Unix(claims.Expires, 0)):
		return errors.New("token has expired")
	case !slices.Contains(audiences(claims.Audience), s.nonce):
		return errors.New("token is bound to another boot")
	}
	return nil
}

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

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("response failed: %v", err)
	}
}
