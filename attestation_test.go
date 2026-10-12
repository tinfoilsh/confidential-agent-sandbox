package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// The adapter returns only the attestation socket's document for this nonce,
// without forwarding owner credentials or exposing other shim endpoints.
func TestRouteAttestationUsesLocalSocket(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "attestation.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	nonce := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
	document := `{"nonce":"` + nonce + `","evidence":"from-runtime-socket"}`
	requests := make(chan *http.Request, 2)
	localServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r
		if r.URL.Query().Get("nonce") != nonce {
			http.Error(w, "invalid nonce", http.StatusBadRequest)
			return
		}
		io.WriteString(w, document)
	})}
	go localServer.Serve(listener)
	defer localServer.Close()
	local := attestationClient(socket)
	defer local.CloseIdleConnections()
	server := httptest.NewTLSServer(routeHandler(local))
	defer server.Close()
	request, _ := http.NewRequest(http.MethodGet, server.URL+attestationPath+"?nonce="+nonce, nil)
	request.Header.Set("Authorization", "Bearer owner-permit")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != document {
		t.Fatalf("attestation response: %d %s %v", response.StatusCode, body, err)
	}
	forwarded := <-requests
	if forwarded.Method != http.MethodGet || forwarded.URL.Path != attestationPath || forwarded.URL.RawQuery != "nonce="+nonce || forwarded.Header.Get("Authorization") != "" {
		t.Fatalf("wrong socket request: %+v", forwarded)
	}
	for _, path := range []string{"/bootstrap", "/.well-known/tinfoil-metrics", "/.well-known/tinfoil-certificate"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("unrelated endpoint %s returned %d", path, response.StatusCode)
		}
	}
	response, err = server.Client().Post(server.URL+"/enroll", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("enrollment bypassed owner authentication: %d", response.StatusCode)
	}
	select {
	case request := <-requests:
		t.Fatalf("unrelated request reached socket: %s", request.URL)
	default:
	}
	response, err = server.Client().Get(server.URL + attestationPath + "?nonce=wrong")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("socket rejection was hidden: %d", response.StatusCode)
	}
	<-requests
	localServer.Close()
	response, err = server.Client().Get(server.URL + attestationPath + "?nonce=" + nonce)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("missing socket returned %d", response.StatusCode)
	}
}
