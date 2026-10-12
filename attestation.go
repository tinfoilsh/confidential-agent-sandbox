package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

const attestationPath = "/.well-known/tinfoil-attestation"
const maxAttestationBytes = 32 << 20

// enrollmentCertificate proves possession of the runtime's attested boot key.
// Clients authenticate that key through attestation, not a WebPKI certificate.
func enrollmentCertificate(path, domain string) (tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return tls.Certificate{}, errors.New("expected a PKCS#8 boot key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, errors.New("boot key cannot sign")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := &x509.Certificate{
		SerialNumber: serial, DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

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
func (s *sandbox) routeHandler(local *http.Client) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", s.handler())
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
