// Command workspace-attestation serves health, public attestation documents and the
// measured owner's EHBP-sealed API.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

const (
	ehbpKeyPath   = "/run/tinfoil/keys/sandbox-ehbp/private_key.pem"
	sandboxUser   = "sandbox"
	systemdMarker = "/run/systemd/system"
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
	owner, err := ownerAPI()
	if err != nil {
		return err
	}
	routeServer := &http.Server{
		Addr: "127.0.0.1:8443", Handler: routeHandler(local, owner),
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
	// Draining lets a request admitted before the systemd handoff reply.
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

// ownerAPI serves the measured owner, or nothing when the launch measured no owner.
func ownerAPI() (http.Handler, error) {
	measured := os.Getenv("SANDBOX_OWNER_PUBLIC_KEY")
	if measured == "" {
		log.Print("no SANDBOX_OWNER_PUBLIC_KEY is measured; the owner API is disabled")
		return nil, nil
	}
	key, err := parseOwnerKey(measured)
	if err != nil {
		return nil, err
	}
	instance := os.Getenv("SANDBOX_INSTANCE_ID")
	if !instancePattern.MatchString(instance) {
		return nil, errors.New("SANDBOX_INSTANCE_ID must be a lowercase UUID")
	}
	ehbp, err := loadEHBPKey(ehbpKeyPath)
	if err != nil {
		return nil, err
	}
	account, err := user.Lookup(sandboxUser)
	if err != nil {
		return nil, err
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if err := errors.Join(uidErr, gidErr); err != nil {
		return nil, err
	}
	systemd := func() bool { _, err := os.Stat(systemdMarker); return err == nil }
	owner := &ownerServer{key: key, instance: instance, now: time.Now,
		workspace: &workspace{instance: instance, monitor: "/run/monitor", uid: uid, gid: gid, unlock: "/usr/local/bin/workspace-unlock",
			network: func(ctx context.Context) error {
				if !systemd() {
					return nil
				}
				return exec.CommandContext(ctx, "systemctl", "restart", "monitor-network.service").Run()
			}},
		shells: &shells{
			command: func() *exec.Cmd { return exec.Command("/usr/sbin/runuser", "-l", sandboxUser) },
			ready: func() error {
				if !systemd() {
					return ownerError{"the workspace is locked; enroll it to unlock it first", http.StatusConflict}
				}
				return nil
			}}}
	return sealedOnly(ehbp, owner), nil
}
