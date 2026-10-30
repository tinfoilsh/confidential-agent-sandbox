package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"maps"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

const (
	ownerRequestContext = "tinfoil owner request v3\x00"
	ownerProtocol       = "sandbox-owner-v1"
	// requestWindow is how far, in milliseconds, a request's time may be from this
	// sandbox's clock in either direction.
	requestWindow = 60_000

	maxNonces     = 1 << 14
	maxOwnerBytes = 512 << 10
)

var instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type ownerEnvelope struct {
	Request   string `json:"request"`
	Signature string `json:"signature"`
}

// ownerRequest is the part of the shared signed request the sandbox checks.
type ownerRequest struct {
	Protocol string `json:"protocol"`
	Resource string `json:"resource"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Body     string `json:"body"`
	IssuedAt int64  `json:"issued_at"`
	Nonce    string `json:"nonce"`
}

// ownerServer authenticates requests signed by the measured owner for this instance.
type ownerServer struct {
	key       ed25519.PublicKey
	instance  string
	workspace *workspace
	shells    *shells
	now       func() time.Time

	mu     sync.Mutex
	nonces map[string]int64
}

// ownerError is a failure the owner sees; class names the shared contract's error.
type ownerError struct {
	class  string
	status int
}

func (e ownerError) Error() string { return e.class }

var (
	errMalformed = ownerError{"malformed", http.StatusBadRequest}
	errSignature = ownerError{"invalid_signature", http.StatusUnauthorized}
	errProtocol  = ownerError{"wrong_protocol", http.StatusUnauthorized}
	errResource  = ownerError{"wrong_resource", http.StatusUnauthorized}
	errFuture    = ownerError{"request_time_in_future", http.StatusUnauthorized}
	errExpired   = ownerError{"request_expired", http.StatusUnauthorized}
	errReplayed  = ownerError{"replayed", http.StatusConflict}
	errBusy      = ownerError{"owner_busy", http.StatusServiceUnavailable}
)

// respond encodes an effect's value, or its failure as {"error": ...}.
func respond(w http.ResponseWriter, value any, err error) {
	status := http.StatusOK
	if err != nil {
		status = http.StatusBadRequest
		var known ownerError
		if errors.As(err, &known) {
			status = known.status
		}
		// The sandbox's clock lets an owner whose clock differs re-sign on it.
		value = map[string]any{"error": err.Error(), "now": time.Now().UnixMilli()}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

// sealedOnly refuses owner requests that are not EHBP-sealed to the attested sandbox key.
func sealedOnly(key *identity.Identity, next http.Handler) http.Handler {
	sealed := key.Middleware()(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(protocol.EncapsulatedKeyHeader) == "" || r.ContentLength == 0 {
			http.Error(w, "owner requests must be EHBP-sealed", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*maxOwnerBytes)
		sealed.ServeHTTP(w, r)
	})
}

func (s *ownerServer) clock() int64 { return s.now().UnixMilli() }

func (s *ownerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxOwnerBytes+1))
	if err != nil || len(raw) > maxOwnerBytes {
		respond(w, nil, errMalformed)
		return
	}
	call, body, err := s.open(raw)
	if err != nil {
		respond(w, nil, err)
		return
	}
	effect := s.route(call, body)
	if effect == nil {
		respond(w, nil, errMalformed)
		return
	}
	// Consume nonces before dispatch.
	if err := s.reserve(call); err != nil {
		respond(w, nil, err)
		return
	}
	value, err := effect(r.Context())
	respond(w, value, err)
}

// open verifies an envelope over its exact signed bytes and returns its request and body.
func (s *ownerServer) open(raw []byte) (ownerRequest, []byte, error) {
	var e ownerEnvelope
	var call ownerRequest
	if json.Unmarshal(raw, &e) != nil {
		return call, nil, errMalformed
	}
	signed, requestErr := base64.RawURLEncoding.DecodeString(e.Request)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(e.Signature)
	if requestErr != nil || signatureErr != nil {
		return call, nil, errMalformed
	}
	digest := sha256.Sum256(signed)
	if !ed25519.Verify(s.key, append([]byte(ownerRequestContext), digest[:]...), signature) {
		return call, nil, errSignature
	}
	if json.Unmarshal(signed, &call) != nil {
		return call, nil, errMalformed
	}
	body, err := base64.RawURLEncoding.DecodeString(call.Body)
	if err != nil {
		return call, nil, errMalformed
	}
	now := s.clock()
	switch {
	case call.Protocol != ownerProtocol:
		return call, nil, errProtocol
	case call.Resource != s.instance:
		return call, nil, errResource
	case call.IssuedAt-now > requestWindow:
		return call, nil, errFuture
	case now-call.IssuedAt > requestWindow:
		return call, nil, errExpired
	}
	return call, body, nil
}

// route binds a request to its effect. Every effect is safe to repeat, so a retry with a
// fresh nonce runs it again.
func (s *ownerServer) route(call ownerRequest, body []byte) func(context.Context) (any, error) {
	if (call.Method == http.MethodGet) != (len(body) == 0) {
		return nil
	}
	switch call.Method + " " + call.Path {
	case "GET /status":
		return func(ctx context.Context) (any, error) { return s.workspace.status(ctx) }
	case "POST /enroll":
		var in enrollInput
		if json.Unmarshal(body, &in) == nil {
			// An unlock outlives a lost connection; a retry waits for it and finds it done.
			return func(ctx context.Context) (any, error) { return s.workspace.enroll(context.WithoutCancel(ctx), in) }
		}
	case "POST /shell":
		var in shellInput
		if json.Unmarshal(body, &in) == nil {
			return func(ctx context.Context) (any, error) { return s.shells.serve(ctx, in) }
		}
	}
	return nil
}

// reserve admits each nonce once until its request's inclusive deadline. When full of
// live nonces it refuses new calls rather than forgetting one that could replay. Every
// entry shares this sandbox's protocol, owner and instance, so the nonce alone is the key.
// The clock is read under mu, so a purged nonce is also expired for every later check.
func (s *ownerServer) reserve(call ownerRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if now-call.IssuedAt > requestWindow {
		return errExpired
	}
	if _, seen := s.nonces[call.Nonce]; seen {
		return errReplayed
	}
	if len(s.nonces) >= maxNonces {
		maps.DeleteFunc(s.nonces, func(_ string, deadline int64) bool { return now > deadline })
	}
	if len(s.nonces) >= maxNonces {
		return errBusy
	}
	if s.nonces == nil {
		s.nonces = map[string]int64{}
	}
	s.nonces[call.Nonce] = call.IssuedAt + requestWindow
	return nil
}

// parseOwnerKey reads the measured owner key.
func parseOwnerKey(value string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	key, err := base64.StdEncoding.DecodeString(encoded)
	if !ok || err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("SANDBOX_OWNER_PUBLIC_KEY must be ed25519: followed by the base64 of an Ed25519 public key")
	}
	return key, nil
}

// loadEHBPKey reads the CVM's attested X25519 key, PKCS#8 encoded as the CVM writes it.
func loadEHBPKey(path string) (*identity.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("sandbox-ehbp key is not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(*ecdh.PrivateKey)
	if err != nil || !ok || private.Curve() != ecdh.X25519() {
		return nil, errors.New("sandbox-ehbp key must be an X25519 private key")
	}
	stored, err := json.Marshal(identity.IdentityStore{PublicKey: private.PublicKey().Bytes(), SecretKey: private.Bytes(),
		KEM: hpke.DHKEM(ecdh.X25519()).ID(), KDF: hpke.HKDFSHA256().ID(), AEAD: hpke.AES256GCM().ID()})
	if err != nil {
		return nil, err
	}
	return identity.Import(stored)
}
