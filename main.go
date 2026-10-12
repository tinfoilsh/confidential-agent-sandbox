// Command workspace-enroll authenticates the boot-bound owner and opens the volume.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	listen = ":8080" // Shim health endpoint.

	hostKey = "/run/workspace/host_key"

	volumeTimeout = 10 * time.Second

	volumeFormat byte = 2 // Argon2id
	opUnlock     byte = 'u'
	opInitialize byte = 'i'

	statusOK       = "ok"
	statusRejected = "rejected"

	maxStatusBytes = 1 << 8
	maxEnrollBytes = 1 << 16
	volumeKeyBytes = 32
)

var (
	disk          = "/mnt/disk"
	volumeControl = "/run/tinfoil/volumes/workspace/control.sock"
)

type sandbox struct {
	sshKey string

	done context.CancelFunc

	mu       sync.Mutex // Guards enrolled and opened.
	enrolled bool
	opened   []byte // Receipt of the enrollment that unlocked the volume.
}

func main() {
	var err error
	switch {
	case len(os.Args) == 2 && os.Args[1] == "--owner-key":
		var line string
		line, err = ownerSSHKey(os.Getenv("SANDBOX_OWNER_PUBLIC_KEY"))
		if err == nil {
			fmt.Print(line)
		}
	case len(os.Args) == 2 && os.Args[1] == "--unlock":
		err = forwardUnlock(os.Stdin)
	case len(os.Args) == 1:
		err = run()
	default:
		err = errors.New("usage: workspace-enroll [--owner-key | --unlock]")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := ownerSSHKey(os.Getenv("SANDBOX_OWNER_PUBLIC_KEY")); err != nil {
		return err
	}
	box := &sandbox{}
	keyData, err := os.ReadFile(hostKey + ".pub")
	if err != nil {
		return err
	}
	box.sshKey = strings.TrimSpace(string(keyData))
	box.enrolled = box.sealed()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	box.done = stop

	certificate, err := enrollmentCertificate(hostKey, "sandbox.invalid")
	if err != nil {
		return err
	}
	local := attestationClient("/tinfoil/attestation.sock")
	defer local.CloseIdleConnections()
	routeServer := &http.Server{
		Addr: "127.0.0.1:8443", Handler: box.routeHandler(local),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}},
	}
	defer routeServer.Close()
	server := &http.Server{
		Addr:              listen,
		Handler:           box.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	defer server.Close()
	// Only the SSH helper's Unix socket serves unlock; TCP serves public health/attestation.
	_ = os.Remove(unlockSocket)
	listener, err := net.Listen("unix", unlockSocket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(unlockSocket, 0600); err != nil {
		return err
	}
	// The pinned Ubuntu image's sandbox account is uid 1000.
	if err := os.Chown(unlockSocket, 1000, -1); err != nil {
		return err
	}
	unlockServer := &http.Server{Handler: box.unlockHandler(), ReadHeaderTimeout: 10 * time.Second}
	defer unlockServer.Close()
	served := make(chan error, 3)
	go func() { served <- unlockServer.Serve(listener) }()
	go func() { served <- server.ListenAndServe() }()
	go func() { served <- routeServer.ListenAndServeTLS("", "") }()
	log.Print("workspace waiting for owner SSH unlock")
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(unlockServer.Shutdown(shutdown), server.Shutdown(shutdown), routeServer.Shutdown(shutdown))
}

func (s *sandbox) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func (s *sandbox) unlockHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /unlock", s.enroll)
	return mux
}

// The private Unix socket accepts only the SSH-authenticated owner's unlock helper.
func (s *sandbox) enroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Volume          []byte `json:"volume"`
		MonitorIdentity string `json:"monitor_identity"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrollBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		reply(w, http.StatusBadRequest, failure{"invalid unlock request"})
		return
	}
	defer clear(body.Volume)
	if decoder.Decode(new(any)) != io.EOF || len(body.Volume) != volumeKeyBytes {
		reply(w, http.StatusBadRequest, failure{"volume must encode a 32-byte workspace key"})
		return
	}
	if _, err := ssh.ParsePrivateKey([]byte(body.MonitorIdentity)); err != nil {
		reply(w, http.StatusBadRequest, failure{"invalid Monitor agent identity"})
		return
	}
	// Serialize the unlock and all disk changes.
	s.mu.Lock()
	defer s.mu.Unlock()
	enrollment := s.receipt(body.Volume, body.MonitorIdentity)
	if s.enrolled {
		sealed, err := os.ReadFile(filepath.Join(disk, ".enrollment"))
		if err == nil && subtle.ConstantTimeCompare(sealed, enrollment) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		log.Printf("enrollment refused: an owner is already enrolled for this boot")
		reply(w, http.StatusConflict, failure{"sandbox is already enrolled"})
		return
	}
	// The volume worker unlocks once per boot, so a request that failed after the unlock
	// can finish only with the same values.
	if s.opened == nil {
		if err := open(body.Volume); err != nil {
			log.Printf("workspace refused the key: %v", err)
			reply(w, http.StatusForbidden, failure{"workspace key refused"})
			return
		}
		s.opened = enrollment
	} else if subtle.ConstantTimeCompare(s.opened, enrollment) != 1 {
		log.Printf("enrollment refused: another enrollment opened the workspace")
		reply(w, http.StatusConflict, failure{"workspace was opened by another enrollment"})
		return
	}
	if err := seal([]byte(body.MonitorIdentity), enrollment); err != nil {
		log.Printf("workspace provisioning failed: %v", err)
		reply(w, http.StatusInternalServerError, failure{"workspace could not be provisioned"})
		return
	}
	s.enrolled = true
	log.Print("workspace enrolled its owner")
	w.WriteHeader(http.StatusNoContent)
	s.done()
}

// receipt digests every enrollment value, so after a lost response only an identical
// retry is acknowledged. The receipt stays inside the encrypted workspace.
// The first line names this boot's key, since the disk outlives the boot.
func (s *sandbox) receipt(volumeKey []byte, identity string) []byte {
	data, _ := json.Marshal(struct {
		Volume   []byte
		Identity string
	}{volumeKey, identity})
	defer clear(data)
	return fmt.Appendf(nil, "%s\n%x\n", s.sshKey, sha256.Sum256(data))
}

// sealed reports whether this boot's enrollment finished. A restart after the unlock
// finds the disk open, possibly with an earlier boot's enrollment on it.
func (s *sandbox) sealed() bool {
	data, err := os.ReadFile(filepath.Join(disk, ".enrollment"))
	return err == nil && bytes.HasPrefix(data, []byte(s.sshKey+"\n"))
}

// disk is a mount before any volume is behind it, so only the device changing proves the unlock.
func open(key []byte) error {
	locked, err := device(disk)
	if err != nil {
		return err
	}
	if err := unlock(key); err != nil {
		return err
	}
	unlocked, err := device(disk)
	if err != nil {
		return err
	}
	if unlocked == locked {
		return errors.New("volume worker reported success without mounting the workspace")
	}
	return nil
}

func unlock(key []byte) error {
	status, err := control(opInitialize, key)
	if err != nil {
		return err
	}
	if status == statusRejected {
		if status, err = control(opUnlock, key); err != nil {
			return err
		}
	}
	if status != statusOK {
		return fmt.Errorf("volume worker answered %q", status)
	}
	return nil
}

// No read deadline: a first unlock formats the volume, which takes minutes on a large disk.
func control(operation byte, key []byte) (string, error) {
	packet := append([]byte{volumeFormat, operation}, key...)
	defer clear(packet)
	connection, err := net.Dial("unixpacket", volumeControl)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if err := connection.SetWriteDeadline(time.Now().Add(volumeTimeout)); err != nil {
		return "", err
	}
	if _, err := connection.Write(packet); err != nil {
		return "", err
	}
	var reply [maxStatusBytes]byte
	n, err := connection.Read(reply[:])
	if err != nil {
		return "", err
	}
	return string(reply[:n]), nil
}

func device(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Sys().(*syscall.Stat_t).Dev, nil
}

// seal leaves the enrollment on the disk it opened, so a restart inside a live CVM stages
// it without a second enrollment. The receipt is written last and marks it complete.
func seal(identity, enrollment []byte) error {
	for _, file := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{".monitor.identity", identity, 0o600}, {".enrollment", enrollment, 0o600}} {
		if err := os.WriteFile(filepath.Join(disk, file.name), file.data, file.mode); err != nil {
			return err
		}
	}
	syscall.Sync()
	return nil
}

type failure struct {
	Error string `json:"error"`
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("response failed: %v", err)
	}
}
