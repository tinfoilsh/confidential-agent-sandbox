// The executor owns the workspace. It runs the shell and reads and writes
// files on behalf of mcp-server, which reaches it over a unix socket on a
// shared volume — the only channel into this container, which has no
// network of its own (see tinfoil-config.yml). That separation is what
// makes "the sandbox has no network access" true for the commands the
// model runs: mcp-server needs a listener to answer the router, the
// executor does not.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// workspace is the directory the shell runs in and the file tools are
// confined to. It is a var only so tests can point it somewhere writable.
var workspace = "/workspace"

const (
	socketPath = "/run/execsock/exec.sock"

	// execTimeout must stay below the router's three-minute per-call
	// budget, with room for the response to travel: a command that gets
	// killed here still returns output the model can act on, whereas one
	// that outlives the router's deadline returns nothing at all.
	execTimeout = 120 * time.Second

	// maxStreamBytes caps stdout and stderr independently. Whatever the
	// executor returns is headed for a model's context window, so a
	// runaway `yes` or a cat of a binary is truncated to something a turn
	// can survive rather than allowed to fill it.
	maxStreamBytes = 128 << 10

	// maxFileBytes bounds a single file through /read and /write. The
	// editor tools carry file contents inline as JSON, and nothing the
	// model can usefully edit is larger than this.
	maxFileBytes = 8 << 20
)

// workspaceRoot is the *os.Root handle shared by /read and /write.
// openat2(RESOLVE_BENEATH) rejects any path that escapes /workspace, so a
// symlink the shell planted cannot turn a file tool into a read of the
// container's root filesystem. /exec is deliberately not confined this
// way: it is a shell, and the whole container is its sandbox.
var workspaceRoot *os.Root

type execRequest struct {
	Command string `json:"command"`
}

type execResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

type readRequest struct {
	Path string `json:"path"`
}

type readResponse struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

type writeRequest struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

type writeResponse struct {
	Path string `json:"path"`
	Size int    `json:"size"`
}

// handleExec runs one command under /bin/sh. Calls are not serialized: the
// router holds an exclusive lease on this sandbox, so the only concurrency
// here is a model issuing parallel tool calls into its own workspace, and
// making those wait on each other would deadlock nothing but help nobody.
func handleExec(w http.ResponseWriter, r *http.Request) {
	var req execRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Command == "" {
		respondError(w, http.StatusBadRequest, "command is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", req.Command)
	cmd.Dir = workspace
	// Own process group, so a timeout kills the whole tree rather than
	// leaving orphaned grandchildren burning the sandbox's CPU for the
	// rest of the VM's life.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }

	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		// Partial output is worth more than a bare timeout: it usually
		// says which step hung.
		respondJSON(w, http.StatusOK, execResponse{
			Stdout:   stdout.String(),
			Stderr:   stderr.String() + fmt.Sprintf("\ncommand timed out after %s and was killed", execTimeout),
			ExitCode: -1,
		})
		return
	}

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			respondError(w, http.StatusInternalServerError, "exec failed: "+err.Error())
			return
		}
		exitCode = exitErr.ExitCode()
	}

	respondJSON(w, http.StatusOK, execResponse{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	})
}

func handleRead(w http.ResponseWriter, r *http.Request) {
	var req readRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	rel, err := relativePath(req.Path)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	info, err := workspaceRoot.Stat(rel)
	switch {
	case os.IsNotExist(err):
		respondError(w, http.StatusNotFound, "file not found: "+req.Path)
		return
	case err != nil:
		respondError(w, http.StatusBadRequest, err.Error())
		return
	case info.IsDir():
		respondError(w, http.StatusBadRequest, "path is a directory: "+req.Path)
		return
	case info.Size() > maxFileBytes:
		respondError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("file is %d bytes, larger than the %d-byte limit — use the shell to work with it", info.Size(), maxFileBytes))
		return
	}

	data, err := workspaceRoot.ReadFile(rel)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, readResponse{Path: req.Path, Contents: base64.StdEncoding.EncodeToString(data)})
}

func handleWrite(w http.ResponseWriter, r *http.Request) {
	var req writeRequest
	// Base64 inflates by 4/3; the envelope covers that plus the JSON.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*maxFileBytes)).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			respondError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("payload exceeds %d bytes", maxErr.Limit))
			return
		}
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	rel, err := relativePath(req.Path)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Contents)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid base64 contents")
		return
	}
	if len(data) > maxFileBytes {
		respondError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file exceeds %d bytes", maxFileBytes))
		return
	}
	if err := workspaceRoot.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := workspaceRoot.WriteFile(rel, data, 0o644); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, writeResponse{Path: req.Path, Size: len(data)})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func main() {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		log.Fatalf("open workspace root %s: %v", workspace, err)
	}
	defer root.Close()
	workspaceRoot = root

	mux := http.NewServeMux()
	mux.HandleFunc("POST /exec", handleExec)
	mux.HandleFunc("POST /read", handleRead)
	mux.HandleFunc("POST /write", handleWrite)
	mux.HandleFunc("GET /health", handleHealth)

	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("removing stale socket: %v", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen unix %s: %v", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}

	log.Printf("executor listening on unix:%s", socketPath)
	log.Fatal(http.Serve(listener, mux))
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}

// relativePath turns a tool-supplied path into one relative to the
// workspace. Escapes are not rejected here — *os.Root does that, and
// doing it twice invites the two checks to disagree.
func relativePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("path is required")
	}
	if filepath.IsAbs(p) {
		rel, err := filepath.Rel(workspace, p)
		if err != nil {
			return "", fmt.Errorf("path outside %s: %s", workspace, p)
		}
		return rel, nil
	}
	return p, nil
}

// cappedBuffer collects at most maxStreamBytes and then reports how much
// it dropped. Truncating in the middle of a command is better than the
// alternatives: the executor cannot know how much output is coming, and a
// command's first 128 KB is almost always the part worth reading.
type cappedBuffer struct {
	buf     bytes.Buffer
	dropped int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := maxStreamBytes - c.buf.Len()
	if room > len(p) {
		room = len(p)
	}
	if room > 0 {
		c.buf.Write(p[:room])
	}
	c.dropped += len(p) - room
	// Report a full write: a short count makes the child see a write
	// error for output we chose to discard.
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	if c.dropped == 0 {
		return c.buf.String()
	}
	return fmt.Sprintf("%s\n[truncated: %d more bytes]", c.buf.String(), c.dropped)
}
