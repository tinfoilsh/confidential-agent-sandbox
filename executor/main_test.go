package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withWorkspace points the file handlers at a temp directory. The exec
// handler still runs commands with cmd.Dir = /workspace, so tests that
// need both are the ones that skip when it does not exist.
func withWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	previousDir := workspace
	workspace = dir
	t.Cleanup(func() { workspace = previousDir })
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	previous := workspaceRoot
	workspaceRoot = root
	t.Cleanup(func() { workspaceRoot = previous })
	return dir
}

func post(t *testing.T, handler http.HandlerFunc, path string, body any) (int, map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(encoded))))
	var decoded map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response %q: %v", w.Body.String(), err)
	}
	return w.Code, decoded
}

func TestExec(t *testing.T) {
	withWorkspace(t)
	status, resp := post(t, handleExec, "/exec", execRequest{Command: "echo out; echo err >&2; exit 3"})
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if resp["stdout"] != "out\n" || resp["stderr"] != "err\n" {
		t.Errorf("stdout/stderr = %q/%q", resp["stdout"], resp["stderr"])
	}
	if resp["exit_code"] != float64(3) {
		t.Errorf("exit_code = %v, want the command's own status", resp["exit_code"])
	}
}

func TestExecRejectsEmptyCommand(t *testing.T) {
	if status, _ := post(t, handleExec, "/exec", execRequest{}); status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
}

// TestExecTruncatesRunawayOutput: a command that prints without bound must
// not be able to fill the model's context window.
func TestExecTruncatesRunawayOutput(t *testing.T) {
	withWorkspace(t)
	status, resp := post(t, handleExec, "/exec", execRequest{
		Command: "for i in $(seq 1 40000); do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done",
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	stdout, _ := resp["stdout"].(string)
	if len(stdout) > maxStreamBytes+128 {
		t.Errorf("stdout is %d bytes, want it capped near %d", len(stdout), maxStreamBytes)
	}
	if !strings.Contains(stdout, "[truncated:") {
		t.Error("truncated output did not say it was truncated")
	}
}

func TestReadWriteRoundTrip(t *testing.T) {
	dir := withWorkspace(t)

	status, resp := post(t, handleWrite, "/write", writeRequest{
		Path:     "notes/todo.md",
		Contents: base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if status != http.StatusOK {
		t.Fatalf("write status = %d (%v)", status, resp)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes/todo.md")); err != nil {
		t.Fatalf("write did not create the file: %v", err)
	}

	// An absolute /workspace path and a relative one must land on the
	// same file — the model uses both interchangeably.
	status, resp = post(t, handleRead, "/read", readRequest{Path: filepath.Join(workspace, "notes/todo.md")})
	if status != http.StatusOK {
		t.Fatalf("read status = %d (%v)", status, resp)
	}
	contents, _ := resp["contents"].(string)
	decoded, err := base64.StdEncoding.DecodeString(contents)
	if err != nil || string(decoded) != "hello" {
		t.Errorf("read back %q (%v), want hello", decoded, err)
	}
}

func TestReadMissingFile(t *testing.T) {
	withWorkspace(t)
	if status, _ := post(t, handleRead, "/read", readRequest{Path: "nope.txt"}); status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", status)
	}
}

func TestReadRejectsDirectory(t *testing.T) {
	dir := withWorkspace(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if status, _ := post(t, handleRead, "/read", readRequest{Path: "sub"}); status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", status)
	}
}

// TestFileToolsStayInsideWorkspace: the shell shares this filesystem and
// can plant a symlink or hand back a traversing path, so the file
// endpoints must refuse to follow either one out of /workspace.
func TestFileToolsStayInsideWorkspace(t *testing.T) {
	dir := withWorkspace(t)
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"traversal": "../../etc/passwd",
		"symlink":   "link",
		"absolute":  "/etc/passwd",
	} {
		t.Run(name, func(t *testing.T) {
			if status, _ := post(t, handleRead, "/read", readRequest{Path: path}); status == http.StatusOK {
				t.Errorf("read escaped the workspace via %s", name)
			}
			status, _ := post(t, handleWrite, "/write", writeRequest{
				Path: path, Contents: base64.StdEncoding.EncodeToString([]byte("x")),
			})
			if status == http.StatusOK {
				t.Errorf("write escaped the workspace via %s", name)
			}
		})
	}
	if data, _ := os.ReadFile(outside); string(data) != "secret" {
		t.Error("a write reached a file outside the workspace")
	}
}

func TestWriteRejectsOversizeFile(t *testing.T) {
	withWorkspace(t)
	status, _ := post(t, handleWrite, "/write", writeRequest{
		Path:     "big.bin",
		Contents: base64.StdEncoding.EncodeToString(make([]byte, maxFileBytes+1)),
	})
	if status != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", status)
	}
}

func TestReadRejectsOversizeFile(t *testing.T) {
	dir := withWorkspace(t)
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), make([]byte, maxFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if status, _ := post(t, handleRead, "/read", readRequest{Path: "big.bin"}); status != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", status)
	}
}
