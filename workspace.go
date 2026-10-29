package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	agentIdentityFile = "identity"
	monitorPinFile    = "known_hosts"
	monitorPinHost    = "monitor "
	// Formatting a new workspace can take minutes.
	unlockTimeout = 10 * time.Minute
)

var (
	volumeStates        = []string{"unlocked", "locked_blank", "locked_initialized", "locked_unknown"}
	errIdentityConflict = ownerError{"identity_conflict", http.StatusConflict}
)

// workspace owns this boot's Monitor credentials in /run/monitor and its volume unlock.
type workspace struct {
	instance string
	monitor  string // directory of the agent identity and Monitor pin
	uid, gid int    // the sandbox user, who reads both
	unlock   string // workspace-unlock
	// network restarts monitor-network once systemd runs it.
	network func(context.Context) error

	mu sync.Mutex
}

type status struct {
	Protocol       string  `json:"protocol"`
	InstanceID     string  `json:"instance_id"`
	Volume         string  `json:"volume"`
	AgentPublicKey *string `json:"agent_public_key"`
	MonitorHostKey *string `json:"monitor_host_key"`
}

type enrollInput struct {
	AgentSeed       string `json:"agent_seed"`
	MonitorHostKey  string `json:"monitor_host_key"`
	DiskKey         string `json:"disk_key"`
	AllowInitialize bool   `json:"allow_initialize"`
}

// status reports the volume as mounted or as the volume worker sees it, never inferred
// from missing files, and the agent identity and Monitor pin this boot holds.
func (w *workspace) status(ctx context.Context) (status, error) {
	s := status{Protocol: ownerProtocol, InstanceID: w.instance}
	volume, err := w.run(ctx, nil, "--status")
	s.Volume = strings.TrimSpace(volume)
	if err != nil || !slices.Contains(volumeStates, s.Volume) {
		return s, fmt.Errorf("workspace status: %q %v", s.Volume, err)
	}
	agent, err := w.identity()
	if agent != nil {
		key := authorizedKey(agent.PublicKey())
		s.AgentPublicKey = &key
	}
	pin, pinErr := os.ReadFile(filepath.Join(w.monitor, monitorPinFile))
	if pinErr == nil {
		key := strings.TrimSuffix(strings.TrimPrefix(string(pin), monitorPinHost), "\n")
		s.MonitorHostKey = &key
	} else if !errors.Is(pinErr, os.ErrNotExist) {
		err = errors.Join(err, pinErr)
	}
	return s, err
}

// enroll installs the agent identity and Monitor pin, then unlocks the volume with the
// disk key. Re-enrolling the same identity only repins a restarted Monitor. Initializing
// is left to the volume worker, which refuses a nonblank disk.
func (w *workspace) enroll(ctx context.Context, in enrollInput) (status, error) {
	seed, seedErr := base64.RawURLEncoding.DecodeString(in.AgentSeed)
	disk, diskErr := base64.RawURLEncoding.DecodeString(in.DiskKey)
	defer clear(seed)
	defer clear(disk)
	pin, pinErr := monitorPin(in.MonitorHostKey)
	if seedErr != nil || diskErr != nil || pinErr != nil || len(seed) != ed25519.SeedSize || len(disk) != 32 {
		return status{}, errors.New("enroll needs a 32-byte agent_seed and disk_key and an ssh-ed25519 monitor_host_key")
	}
	agent := ed25519.NewKeyFromSeed(seed)
	defer clear(agent)
	public, err := ssh.NewPublicKey(agent.Public())
	if err != nil {
		return status{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	existing, err := w.identity()
	if err != nil {
		return status{}, err
	}
	if existing != nil && !bytes.Equal(existing.PublicKey().Marshal(), public.Marshal()) {
		return status{}, errIdentityConflict
	}
	changed, err := w.install(monitorPinFile, pin)
	if err == nil && existing == nil {
		var block *pem.Block
		if block, err = ssh.MarshalPrivateKey(agent, ""); err == nil {
			private := pem.EncodeToMemory(block)
			clear(block.Bytes)
			_, err = w.install(agentIdentityFile, private)
			clear(private)
			changed = true
		}
	}
	if err == nil && changed {
		err = w.network(ctx)
	}
	if err != nil {
		return status{}, err
	}
	args := []string{}
	if in.AllowInitialize {
		args = append(args, "--initialize")
	}
	unlockCtx, cancel := context.WithTimeout(ctx, unlockTimeout)
	defer cancel()
	if reply, err := w.run(unlockCtx, disk, args...); err != nil {
		return status{}, ownerError{"unlock failed: " + strings.TrimSpace(reply), http.StatusBadGateway}
	}
	return w.status(ctx)
}

// identity is the installed agent identity, or nil.
func (w *workspace) identity() (ssh.Signer, error) {
	data, err := os.ReadFile(filepath.Join(w.monitor, agentIdentityFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return ssh.ParsePrivateKey(data)
}

// install atomically replaces one file the sandbox user reads, reporting whether it changed.
func (w *workspace) install(name string, data []byte) (bool, error) {
	path := filepath.Join(w.monitor, name)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return false, nil
	}
	if err := os.MkdirAll(w.monitor, 0o750); err != nil {
		return false, err
	}
	if err := os.Chown(w.monitor, -1, w.gid); err != nil {
		return false, err
	}
	file, err := os.CreateTemp(w.monitor, "."+name+"-")
	if err != nil {
		return false, err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	err = errors.Join(err, file.Chown(w.uid, w.gid), file.Sync(), file.Close())
	if err == nil {
		err = os.Rename(file.Name(), path)
	}
	return err == nil, err
}

// run invokes workspace-unlock with input on stdin and returns its output.
func (w *workspace) run(ctx context.Context, input []byte, args ...string) (string, error) {
	command := exec.CommandContext(ctx, w.unlock, args...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	return strings.ToValidUTF8(string(output), ""), err
}

// monitorPin accepts exactly "ssh-ed25519 <key>" and returns its known_hosts line.
func monitorPin(key string) ([]byte, error) {
	parsed, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil || len(rest) != 0 || parsed.Type() != ssh.KeyAlgoED25519 || authorizedKey(parsed) != key {
		return nil, errors.New("monitor_host_key must be one ssh-ed25519 public key without a comment")
	}
	return []byte(monitorPinHost + key + "\n"), nil
}

func authorizedKey(key ssh.PublicKey) string {
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n")
}
