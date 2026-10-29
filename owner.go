package main

import (
	"bytes"
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

	"filippo.io/edwards25519"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

const (
	ownerRequestContext = "tinfoil owner request v2\x00"
	ownerProtocol       = "sandbox-owner-v1"
	// requestWindow is the inclusive age, in milliseconds, of an acceptable request.
	requestWindow = 60_000

	nonceBytes      = 24
	maxSafeInteger  = 1<<53 - 1
	maxNonces       = 1 << 14
	maxOperations   = 4096
	maxResultBytes  = 4 << 20
	maxResultsBytes = 64 << 20
	maxOwnerBytes   = 512 << 10
)

var instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type ownerEnvelope struct {
	Request   string `json:"request"`
	Signature string `json:"signature"`
}

// ownerRequest is the signed owner request; fields stay in contract order.
type ownerRequest struct {
	Protocol   string `json:"protocol"`
	Owner      string `json:"owner"`
	Resource   string `json:"resource"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Body       string `json:"body"`
	Operation  string `json:"operation"`
	Session    string `json:"session"`
	Generation uint64 `json:"generation"`
	IssuedAt   int64  `json:"issued_at"`
	Nonce      string `json:"nonce"`
}

// ownerServer authenticates requests signed by the measured owner for this instance.
type ownerServer struct {
	key       ed25519.PublicKey
	instance  string
	workspace *workspace
	shells    *shells
	now       func() time.Time

	mu          sync.Mutex
	nonces      map[string]int64
	operations  map[string]*operation
	resultBytes int
}

// operation is one effectful request; retries with fresh nonces share its result.
type operation struct {
	content  [sha256.Size]byte
	deadline int64
	done     chan struct{}
	result   *result
}

type result struct {
	status int
	body   []byte
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
	errOwner     = ownerError{"wrong_owner", http.StatusUnauthorized}
	errProtocol  = ownerError{"wrong_protocol", http.StatusUnauthorized}
	errResource  = ownerError{"wrong_resource", http.StatusUnauthorized}
	errFuture    = ownerError{"request_time_in_future", http.StatusUnauthorized}
	errExpired   = ownerError{"request_expired", http.StatusUnauthorized}
	errReplayed  = ownerError{"replayed", http.StatusConflict}
	errConflict  = ownerError{"operation_conflict", http.StatusConflict}
	errBusy      = ownerError{"owner_busy", http.StatusServiceUnavailable}
)

// answer encodes an effect's value, or its failure as {"error": ...}.
func answer(value any, err error) *result {
	status := http.StatusOK
	if err != nil {
		status = http.StatusBadRequest
		var known ownerError
		if errors.As(err, &known) {
			status = known.status
		}
		value = map[string]string{"error": err.Error()}
	}
	body, err := json.Marshal(value)
	if err != nil {
		return answer(nil, err)
	}
	return &result{status, body}
}

func (r *result) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(r.status)
	w.Write(r.body)
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
		answer(nil, errMalformed).write(w)
		return
	}
	call, body, err := s.open(raw, s.clock())
	if err != nil {
		answer(nil, err).write(w)
		return
	}
	effect, tracked := s.route(call, body)
	if effect == nil {
		answer(nil, errMalformed).write(w)
		return
	}
	// Consume nonces before dispatch.
	if err := s.reserve(call); err != nil {
		answer(nil, err).write(w)
		return
	}
	if !tracked {
		effect(r.Context()).write(w)
		return
	}
	op, first, err := s.track(call)
	if err != nil {
		answer(nil, err).write(w)
		return
	}
	if first {
		// An effect outlives a lost connection; retries share it and status reconciles it.
		go s.finish(op, effect, context.WithoutCancel(r.Context()))
	}
	select {
	case <-op.done:
	case <-r.Context().Done():
		return
	}
	if op.result == nil {
		answer(nil, errBusy).write(w)
		return
	}
	op.result.write(w)
}

// open checks an envelope in the shared contract's order and returns its request and body.
func (s *ownerServer) open(raw []byte, now int64) (ownerRequest, []byte, error) {
	var e ownerEnvelope
	var call ownerRequest
	if decodeCanonical(raw, &e) != nil {
		return call, nil, errMalformed
	}
	signed, requestErr := decodeB64U(e.Request, -1)
	signature, signatureErr := decodeB64U(e.Signature, ed25519.SignatureSize)
	if requestErr != nil || signatureErr != nil {
		return call, nil, errMalformed
	}
	if !ed25519.Verify(s.key, append([]byte(ownerRequestContext), signed...), signature) {
		return call, nil, errSignature
	}
	if decodeCanonical(signed, &call) != nil {
		return call, nil, errMalformed
	}
	_, nonceErr := decodeB64U(call.Nonce, nonceBytes)
	body, bodyErr := decodeB64U(call.Body, -1)
	if nonceErr != nil || bodyErr != nil || !validID16(call.Operation) || (call.Session != "" && !validID16(call.Session)) ||
		!strings.HasPrefix(call.Path, "/") || strings.IndexFunc(call.Path, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 ||
		call.Generation > maxSafeInteger || call.IssuedAt < 0 || call.IssuedAt > maxSafeInteger {
		return call, nil, errMalformed
	}
	switch {
	case call.Owner != ownerKeyString(s.key):
		return call, nil, errOwner
	case call.Protocol != ownerProtocol:
		return call, nil, errProtocol
	case call.Resource != s.instance:
		return call, nil, errResource
	case now < call.IssuedAt:
		return call, nil, errFuture
	case now-call.IssuedAt > requestWindow:
		return call, nil, errExpired
	}
	return call, body, nil
}

// route binds a request to its effect and reports whether its result is kept for retries.
// Polls only acknowledge output up to their cursor, so repeating one is harmless.
func (s *ownerServer) route(call ownerRequest, body []byte) (func(context.Context) *result, bool) {
	if call.Generation != 0 || (call.Method == http.MethodGet) != (len(body) == 0) {
		return nil, false
	}
	switch call.Method + " " + call.Path {
	case "GET /status":
		if call.Session == "" {
			return func(ctx context.Context) *result { return answer(s.workspace.status(ctx)) }, false
		}
	case "POST /enroll":
		var in enrollInput
		if call.Session == "" && decodeStrict(body, &in) == nil {
			return func(ctx context.Context) *result { return answer(s.workspace.enroll(ctx, in)) }, true
		}
	case "POST /relink":
		var in relinkInput
		if call.Session == "" && decodeStrict(body, &in) == nil {
			return func(ctx context.Context) *result { return answer(s.workspace.relink(ctx, in)) }, true
		}
	case "POST /shell":
		var in shellInput
		// The signed session names every shell call but open, which creates it.
		if decodeStrict(body, &in) == nil && (in.Action == "open") == (call.Session == "") && (in.Action == "open" || in.ID == call.Session) {
			return func(ctx context.Context) *result { return answer(s.shells.serve(ctx, in)) }, in.Action != "poll"
		}
	}
	return nil, false
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

// track returns the operation a request belongs to and whether this request runs it.
// A retry must repeat the original content and time; only its nonce changes.
func (s *ownerServer) track(call ownerRequest) (*operation, bool, error) {
	call.Nonce = ""
	content, err := contractJSON(call)
	if err != nil {
		return nil, false, errMalformed
	}
	digest := sha256.Sum256(content)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if now-call.IssuedAt > requestWindow {
		return nil, false, errExpired
	}
	if op := s.operations[call.Operation]; op != nil {
		if op.content != digest {
			return nil, false, errConflict
		}
		return op, false, nil
	}
	if len(s.operations) >= maxOperations {
		s.forget(now)
	}
	if len(s.operations) >= maxOperations {
		return nil, false, errBusy
	}
	if s.operations == nil {
		s.operations = map[string]*operation{}
	}
	op := &operation{content: digest, deadline: call.IssuedAt + requestWindow, done: make(chan struct{})}
	s.operations[call.Operation] = op
	return op, true, nil
}

// finish runs an operation and keeps its bounded result until the operation's deadline.
// An effect that outlasts the deadline still completes; later clients reconcile its state.
func (s *ownerServer) finish(op *operation, effect func(context.Context) *result, ctx context.Context) {
	var r *result
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r != nil && len(r.body) <= maxResultBytes && s.resultBytes+len(r.body) > maxResultsBytes {
			s.forget(s.clock())
		}
		if r != nil && len(r.body) <= maxResultBytes && s.resultBytes+len(r.body) <= maxResultsBytes {
			op.result = r
			s.resultBytes += len(r.body)
		}
		close(op.done)
	}()
	r = effect(ctx)
}

// forget drops finished operations past their deadline; the caller holds mu.
func (s *ownerServer) forget(now int64) {
	maps.DeleteFunc(s.operations, func(_ string, op *operation) bool {
		select {
		case <-op.done:
		default:
			return false
		}
		if now <= op.deadline {
			return false
		}
		if op.result != nil {
			s.resultBytes -= len(op.result.body)
		}
		return true
	})
}

func ownerKeyString(key ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(key)
}

// parseOwnerKey reads the measured owner key. A small-order point would verify forged
// signatures for any message, so only canonical keys outside the torsion subgroup pass.
func parseOwnerKey(value string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if ok && err == nil && len(key) == ed25519.PublicKeySize && ownerKeyString(key) == value {
		point, err := new(edwards25519.Point).SetBytes(key)
		if err == nil && bytes.Equal(point.Bytes(), key) && new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 0 {
			return key, nil
		}
	}
	return nil, errors.New("SANDBOX_OWNER_PUBLIC_KEY must be ed25519: followed by the base64 of a valid Ed25519 public key")
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

// decodeB64U requires the canonical encoding; Go's decoder alone skips CR and LF.
// A negative size accepts any length.
func decodeB64U(text string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != text || (size >= 0 && len(decoded) != size) {
		return nil, errors.New("invalid base64url value")
	}
	return decoded, nil
}

func validID16(id string) bool {
	_, err := decodeB64U(id, 16)
	return err == nil
}

// contractJSON is the deterministic encoding: declared field order, no HTML escaping.
func contractJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// decodeCanonical accepts only the deterministic encoding, rejecting duplicate,
// unknown, reordered or reformatted members.
func decodeCanonical(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	if canonical, err := contractJSON(v); err != nil || !bytes.Equal(canonical, data) {
		return errors.New("not in canonical form")
	}
	return nil
}

// decodeStrict reads one JSON value with no unknown members or trailing data.
func decodeStrict(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}
