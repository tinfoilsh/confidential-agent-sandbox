package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

const attestationPath = "/.well-known/tinfoil-attestation"
const maxAttestationBytes = 32 << 20

func attestationClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// routeHandler exposes only health and the existing attestation socket.
func routeHandler(local *http.Client) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", healthHandler())
	mux.HandleFunc("GET "+attestationPath, func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://attestation"+attestationPath+"?"+r.URL.RawQuery, nil)
		if err != nil {
			http.Error(w, "invalid attestation request", http.StatusBadRequest)
			return
		}
		// No client headers, credentials or body are sent to the attestation socket.
		response, err := local.Do(request)
		if err != nil {
			http.Error(w, "attestation unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, maxAttestationBytes+1))
		if err != nil || len(body) > maxAttestationBytes {
			http.Error(w, "invalid attestation response", http.StatusBadGateway)
			return
		}
		if response.StatusCode != http.StatusOK {
			http.Error(w, "attestation unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	return mux
}
