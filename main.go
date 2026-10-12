// Command workspace-enroll authenticates the boot-bound owner and opens the volume.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
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
)

const (
	listen = ":8080" // Only the shim terminates TLS.

	hostKey = "/run/workspace/host_key"

	volumeTimeout = 10 * time.Second

	volumeFormat byte = 2 // Argon2id
	opUnlock     byte = 'u'
	opInitialize byte = 'i'

	statusOK       = "ok"
	statusRejected = "rejected"

	maxStatusBytes = 1 << 8
	maxEnrollBytes = 1 << 16

	certificateSuffix = "-cert-v01@openssh.com"
)

var (
	disk          = "/mnt/disk"
	volumeControl = "/run/tinfoil/volumes/workspace/control.sock"
)

type monitorRoute struct {
	Domain   string `json:"domain"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	HostKey  string `json:"host_key"`
	Identity string `json:"identity,omitempty"`
}

func (c monitorRoute) valid() bool {
	ip := net.ParseIP(c.IP)
	return ip != nil && ip.To4() != nil && ip.IsGlobalUnicast() && c.Port >= 1 && c.Port <= 65535 && c.Domain != "" &&
		!strings.ContainsAny(c.Domain, "/:@ \r\n") && !strings.ContainsAny(c.HostKey, "\r\n") &&
		(strings.HasPrefix(c.HostKey, "ssh-") || strings.HasPrefix(c.HostKey, "ecdsa-"))
}

type sandbox struct {
	domain string
	owner  *ownerCommitment
	sshKey string

	done context.CancelFunc

	mu       sync.Mutex // Guards enrolled and opened.
	enrolled bool
	opened   []byte // Receipt of the enrollment that unlocked the volume.
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	box := &sandbox{
		domain: os.Getenv("DOMAIN"),
	}
	if box.domain == "" {
		return errors.New("DOMAIN is not set")
	}
	owner, err := parseOwnerCommitment(os.Getenv("SANDBOX_OWNER_KEY_SHA256"), os.Getenv("SANDBOX_OWNER_KEY_ARGON2ID"))
	if err != nil {
		return err
	}
	box.owner = owner
	keyData, err := os.ReadFile(hostKey + ".pub")
	if err != nil {
		return err
	}
	box.sshKey = strings.TrimSpace(string(keyData))
	box.enrolled = box.sealed()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	box.done = stop

	// The shim forwards enrollment after terminating its attested TLS connection.
	server := &http.Server{
		Addr:              listen,
		Handler:           box.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	defer server.Close()
	served := make(chan error, 1)
	go func() { served <- server.ListenAndServe() }()
	log.Printf("workspace %s serving enrollment", box.domain)
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}

func (s *sandbox) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /enroll", s.enroll)
	return mux
}

// The measured owner digest authorizes enrollment before any disk or route changes.
func (s *sandbox) enroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key     string        `json:"key"`
		Volume  string        `json:"volume"`
		Monitor *monitorRoute `json:"monitor"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrollBytes)).Decode(&body); err != nil {
		reply(w, http.StatusBadRequest, failure{"enrollment is not a JSON object naming a key"})
		return
	}
	// An uncontained sandbox enrolls without a Monitor. Reject an unusable one before opening the workspace.
	if route := body.Monitor; route != nil && (!route.valid() || !strings.Contains(route.Identity, "PRIVATE KEY")) {
		reply(w, http.StatusBadRequest, failure{"invalid Monitor enrollment"})
		return
	}
	// Null clears an earlier boot's Monitor configuration.
	monitor, _ := json.Marshal(body.Monitor)
	volumeKey, err := workspaceKey(body.Volume)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"volume must encode a workspace key of 16 to 4096 bytes"})
		return
	}
	defer clear(volumeKey)
	// Serialize owner verification before its memory-hard KDF and all disk changes.
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.owner.matches(volumeKey) {
		reply(w, http.StatusForbidden, failure{"owner key refused"})
		return
	}
	line, err := authorizedKey(body.Key)
	if err != nil {
		log.Printf("enrollment refused: %v", err)
		reply(w, http.StatusBadRequest, failure{"key is not one SSH public key"})
		return
	}
	enrollment := s.receipt(line, volumeKey, body.Monitor)
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
		if err := open(volumeKey); err != nil {
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
	if err := seal(line, monitor, enrollment); err != nil {
		log.Printf("workspace provisioning failed: %v", err)
		reply(w, http.StatusInternalServerError, failure{"workspace could not be provisioned"})
		return
	}
	s.enrolled = true
	log.Printf("workspace %s enrolled its owner", s.domain)
	w.WriteHeader(http.StatusNoContent)
	s.done()
}

// receipt digests every enrollment value, so after a lost response only an identical
// retry is acknowledged. The receipt stays inside the encrypted workspace.
// The first line names this boot's key, since the disk outlives the boot.
func (s *sandbox) receipt(line string, volumeKey []byte, route *monitorRoute) []byte {
	data, _ := json.Marshal(struct {
		Key     string
		Volume  []byte
		Monitor *monitorRoute
	}{line, volumeKey, route})
	return fmt.Appendf(nil, "%s\n%x\n", s.sshKey, sha256.Sum256(data))
}

// sealed reports whether this boot's enrollment finished. A restart after the unlock
// finds the disk open, possibly with an earlier boot's enrollment on it.
func (s *sandbox) sealed() bool {
	data, err := os.ReadFile(filepath.Join(disk, ".enrollment"))
	return err == nil && bytes.HasPrefix(data, []byte(s.sshKey+"\n"))
}

func workspaceKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(key) < minVolumeKeyBytes || len(key) > maxVolumeKeyBytes {
		size := len(key)
		clear(key)
		return nil, fmt.Errorf("workspace key is %d bytes, want %d to %d", size, minVolumeKeyBytes, maxVolumeKeyBytes)
	}
	return key, nil
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
func seal(line string, monitor, enrollment []byte) error {
	for _, file := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{".authorized_keys", []byte(line), 0o644}, {".monitor.json", monitor, 0o600}, {".enrollment", enrollment, 0o600}} {
		if err := os.WriteFile(filepath.Join(disk, file.name), file.data, file.mode); err != nil {
			return err
		}
	}
	syscall.Sync()
	return nil
}

func authorizedKey(line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", errors.New("line is not a type and a key")
	}
	if strings.HasSuffix(fields[0], certificateSuffix) {
		return "", errors.New("line names a certificate, not a key")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", err
	}
	if len(blob) < 4 || len(blob) < 4+int(binary.BigEndian.Uint32(blob)) {
		return "", errors.New("key is not an SSH public key blob")
	}
	if named := string(blob[4 : 4+binary.BigEndian.Uint32(blob)]); named != fields[0] {
		return "", fmt.Errorf("key is a %s, not the %s the line names", named, fields[0])
	}
	return fields[0] + " " + fields[1] + "\n", nil
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
