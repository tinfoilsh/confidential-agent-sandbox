package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
)

const (
	ownerProtocol = "sandbox-owner-v2"
	maxOwnerBytes = 512 << 10
)

var instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ownerServer serves sessions signed by the measured owner for this instance.
type ownerServer struct {
	key        ed25519.PublicKey
	sessionKey noise.DHKey
	instance   string
	workspace  *workspace
	shells     *shells
}

// ownerHello opens a session as RPC or as one shell of the given size.
type ownerHello struct {
	Open string `json:"open"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

// ownerError is a failure the owner sees; class names the shared contract's error.
type ownerError struct {
	class  string
	status int
}

func (e ownerError) Error() string { return e.class }

// respond encodes an effect's value, or its failure as {"error": ...}.
func respond(value any, err error) Reply {
	status := http.StatusOK
	if err != nil {
		status = http.StatusBadRequest
		var known ownerError
		if errors.As(err, &known) {
			status = known.status
		}
		value = map[string]any{"error": err.Error()}
	}
	body, _ := json.Marshal(value)
	return Reply{Status: status, Body: body}
}

func (s *ownerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var hello ownerHello
	c, err := Accept(w, r, s.sessionKey, ownerProtocol+"\x00"+s.instance, s.key, &hello)
	if err != nil {
		return
	}
	switch hello.Open {
	case "rpc":
		c.ServeRPC(r.Context(), maxOwnerBytes, func(ctx context.Context, call Call) Reply {
			effect := s.route(call)
			if effect == nil {
				return respond(nil, errMalformed)
			}
			return respond(effect(ctx))
		})
	case "shell":
		s.shells.serve(r.Context(), c, hello.Cols, hello.Rows)
	default:
		c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
	}
}

// route binds a call to its effect.
func (s *ownerServer) route(call Call) func(context.Context) (any, error) {
	if (call.Method == http.MethodGet) != (len(call.Body) == 0) {
		return nil
	}
	switch call.Method + " " + call.Path {
	case "GET /status":
		return func(ctx context.Context) (any, error) { return s.workspace.status(ctx) }
	case "POST /enroll":
		var in enrollInput
		if json.Unmarshal(call.Body, &in) == nil {
			// An unlock outlives a lost connection; a retry waits for it and finds it done.
			return func(ctx context.Context) (any, error) { return s.workspace.enroll(context.WithoutCancel(ctx), in) }
		}
	}
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
