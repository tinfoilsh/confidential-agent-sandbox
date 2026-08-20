// confidential-agent-sandbox is the workload behind the router's
// agent_sandbox tool profile: one tenant's private Linux workspace,
// reached over MCP, inside its own confidential VM.
//
// The VM's identity is what makes this safe. The router derives two
// values from the end user's cache secret — a pseudonymous sandbox id and
// a sandbox key — and gives only the id to the orchestrator that
// schedules VMs. Before it sends the key, the router attests this
// workload's measurement against the pinned source repo. So an
// operator-compromised orchestrator can hand the router a different VM,
// but not one that passes attestation, and never one that already knows
// a key.
//
// This process therefore has no configuration, no secrets, and no notion
// of who its tenant is. It binds to the first key it is shown and serves
// nobody else for the rest of its life.
package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// listenAddr is the port the CVM shim proxies to; see tinfoil-config.yml.
const listenAddr = ":8000"

// gate is the sandbox's whole authorization story.
//
// The first request with a bearer token claims this sandbox, and every
// later request must present the same one. There is nothing to configure
// and no key to distribute: the router derives the key from the end
// user's secret, and it is only ever sent over a connection whose TLS key
// came out of this VM's attestation.
//
// Trust-on-first-use is sound here because a VM is claimed at most once.
// The orchestrator hands out a warm VM only after it stops being warm, so
// a VM that has already bound a key is never offered to anyone else; one
// that some other party bound first fails every request from its rightful
// owner, which is denial of service — already the orchestrator's to
// commit — and not disclosure.
type gate struct {
	mu  sync.Mutex
	key string
}

// authorize admits a bearer token, binding the sandbox on the first call.
func (g *gate) authorize(bearer string) (status int, message string) {
	if bearer == "" {
		return http.StatusUnauthorized, "missing sandbox key"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.key == "" {
		g.key = bearer
		return 0, ""
	}
	if subtle.ConstantTimeCompare([]byte(g.key), []byte(bearer)) != 1 {
		return http.StatusForbidden, "sandbox key mismatch"
	}
	return 0, ""
}

// bearer pulls the token out of an Authorization header. Anything that is
// not a bearer scheme is treated as no credential at all.
func bearer(header string) string {
	const prefix = "Bearer "
	if len(header) > len(prefix) && header[:len(prefix)] == prefix {
		return header[len(prefix):]
	}
	return ""
}

// authorized wraps a handler in the gate.
func (g *gate) authorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status, message := g.authorize(bearer(r.Header.Get("Authorization"))); status != 0 {
			// Logged without the presented token: it is a live
			// credential for some sandbox, and CVM logs are the one
			// place it must never appear.
			log.Printf("rejected %s: %s", r.URL.Path, message)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"error":%q}`, message)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	ex := newExecutorClient(executorSocket)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "confidential-agent-sandbox",
		Version: "v1",
	}, &mcp.ServerOptions{Instructions: "A private Linux workspace at /workspace that persists across conversations. No network access."})
	addTools(server, ex)

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		// Stateless keeps the transport to a single POST per call: no
		// session header to carry, no standalone SSE stream to hold
		// open, and nothing to resynchronize if the router reconnects
		// mid-conversation. The session state that matters — the
		// workspace — lives on disk, not in the transport.
		Stateless:    true,
		JSONResponse: true,
		// The shim terminates TLS and proxies to this listener over the
		// loopback of the CVM, forwarding the sandbox's own Host header.
		// The SDK's DNS-rebinding guard reads exactly that shape —
		// loopback local address, non-loopback Host — as an attack and
		// would 403 every request. The guard protects browsers on a
		// developer's machine; here the gate above is the real check.
		DisableLocalhostProtection: true,
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp", new(gate).authorized(handler))
	// Unauthenticated on purpose: the orchestrator polls this to decide
	// whether the VM is ready, and it has no key. It learns liveness and
	// nothing else.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if !ex.healthy(r.Context()) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	log.Printf("agent sandbox listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
