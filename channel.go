package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	sessionContext = "tinfoil owner session v1\x00"
	// sessionTimeout bounds the handshake and hello, so unauthenticated sockets do not linger.
	sessionTimeout = 10 * time.Second
	maxCalls       = 4
	// A frame is a flag byte, then data filling the rest of one Noise message.
	frameBytes = noise.MaxMsgLen - 1 - chacha20poly1305.Overhead
	frameMore  = 0
	frameLast  = 1
)

var (
	suite        = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	errMalformed = errors.New("malformed")
	errSignature = errors.New("invalid_signature")
)

// Channel is one authenticated owner session over a WebSocket.
type Channel struct {
	Conn       *websocket.Conn
	send, recv *noise.CipherState
	mu         sync.Mutex
}

// Call is one owner RPC request; its Reply carries the same ID.
type Call struct {
	ID         uint64 `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Generation uint64 `json:"generation"`
	Body       []byte `json:"body"`
}

type Reply struct {
	ID     uint64 `json:"id"`
	Status int    `json:"status"`
	Body   []byte `json:"body"`
}

// LoadKey reads the CVM's attested X25519 key, PKCS#8 encoded as the CVM writes it.
func LoadKey(path string) (noise.DHKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return noise.DHKey{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return noise.DHKey{}, errors.New("owner-session key is not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(*ecdh.PrivateKey)
	if err != nil || !ok || private.Curve() != ecdh.X25519() {
		return noise.DHKey{}, errors.New("owner-session key must be an X25519 private key")
	}
	return noise.DHKey{Private: private.Bytes(), Public: private.PublicKey().Bytes()}, nil
}

// Accept upgrades r and runs an NK handshake bound to prologue. The owner's first message
// signs the handshake hash with its measured key and is decoded into hello.
func Accept(w http.ResponseWriter, r *http.Request, key noise.DHKey, prologue string, owner ed25519.PublicKey, hello any) (*Channel, error) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(noise.MaxMsgLen)
	ctx, cancel := context.WithTimeout(r.Context(), sessionTimeout)
	defer cancel()
	hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNK, Prologue: []byte(prologue), StaticKeypair: key})
	c := &Channel{Conn: conn}
	var message []byte
	if err == nil {
		_, message, err = conn.Read(ctx)
	}
	if err == nil {
		_, _, _, err = hs.ReadMessage(nil, message)
	}
	if err == nil {
		message, c.recv, c.send, err = hs.WriteMessage(nil, nil)
	}
	if err == nil {
		err = conn.Write(ctx, websocket.MessageBinary, message)
	}
	var signed struct {
		Signature []byte `json:"signature"`
	}
	if err == nil {
		message, err = c.Read(ctx, frameBytes)
	}
	if err != nil || json.Unmarshal(message, &signed) != nil || json.Unmarshal(message, hello) != nil {
		err = errMalformed
	} else if !ed25519.Verify(owner, append([]byte(sessionContext), hs.ChannelBinding()...), signed.Signature) {
		err = errSignature
	}
	if err != nil {
		conn.Close(websocket.StatusPolicyViolation, err.Error())
		return nil, err
	}
	return c, nil
}

// Read returns the next whole message, refusing one longer than limit.
func (c *Channel) Read(ctx context.Context, limit int) ([]byte, error) {
	var message []byte
	for {
		_, frame, err := c.Conn.Read(ctx)
		if err == nil {
			frame, err = c.recv.Decrypt(nil, nil, frame)
		}
		if err == nil && (len(frame) == 0 || frame[0] > frameLast || len(message)+len(frame)-1 > limit) {
			err = errMalformed
		}
		if err != nil {
			return nil, err
		}
		message = append(message, frame[1:]...)
		if frame[0] == frameLast {
			return message, nil
		}
	}
}

// Write sends message as frames no other message interleaves with.
func (c *Channel) Write(ctx context.Context, message []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		n := min(len(message), frameBytes)
		flag := byte(frameMore)
		if n == len(message) {
			flag = frameLast
		}
		frame, err := c.send.Encrypt(nil, nil, append([]byte{flag}, message[:n]...))
		if err == nil {
			err = c.Conn.Write(ctx, websocket.MessageBinary, frame)
		}
		if err != nil || flag == frameLast {
			return err
		}
		message = message[n:]
	}
}

// ServeRPC answers calls of at most limit bytes, a few at once and in any order, until the
// socket ends.
func (c *Channel) ServeRPC(ctx context.Context, limit int, serve func(context.Context, Call) Reply) {
	running := make(chan struct{}, maxCalls)
	for {
		var call Call
		message, err := c.Read(ctx, limit)
		if err == nil {
			err = json.Unmarshal(message, &call)
		}
		if err != nil {
			c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
			return
		}
		running <- struct{}{}
		go func() {
			defer func() { <-running }()
			reply := serve(ctx, call)
			reply.ID = call.ID
			out, _ := json.Marshal(reply)
			c.Write(ctx, out)
		}()
	}
}
