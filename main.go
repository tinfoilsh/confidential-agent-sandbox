// Command workspace-attestation serves health and public attestation documents.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	local := attestationClient("/tinfoil/attestation.sock")
	defer local.CloseIdleConnections()
	routeServer := &http.Server{
		Addr: "127.0.0.1:8443", Handler: routeHandler(local),
		ReadHeaderTimeout: 10 * time.Second,
	}
	defer routeServer.Close()
	server := &http.Server{
		Addr:              ":8080",
		Handler:           healthHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	defer server.Close()
	served := make(chan error, 2)
	go func() { served <- server.ListenAndServe() }()
	go func() { served <- routeServer.ListenAndServe() }()
	log.Print("workspace attestation service listening")
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(server.Shutdown(shutdown), routeServer.Shutdown(shutdown))
}

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
