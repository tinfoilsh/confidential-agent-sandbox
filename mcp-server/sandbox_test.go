package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

func TestGateBindsToTheFirstKey(t *testing.T) {
	g := new(gate)
	if status, _ := g.authorize("first-key"); status != 0 {
		t.Fatalf("first key rejected with %d", status)
	}
	if status, _ := g.authorize("first-key"); status != 0 {
		t.Errorf("the bound key was rejected with %d", status)
	}
	if status, _ := g.authorize("another-key"); status != http.StatusForbidden {
		t.Errorf("a second key got %d, want 403 — the sandbox is single-tenant for life", status)
	}
	// Still bound to the original after a rejection.
	if status, _ := g.authorize("first-key"); status != 0 {
		t.Error("a rejected key disturbed the binding")
	}
}

func TestGateRefusesUnauthenticated(t *testing.T) {
	g := new(gate)
	if status, _ := g.authorize(""); status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	// An empty credential must not count as the binding one, or the
	// first unauthenticated probe would lock the sandbox forever.
	if g.key != "" {
		t.Error("an empty key bound the sandbox")
	}
}

func TestBearerIgnoresOtherSchemes(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc":   "abc",
		"bearer abc":   "",
		"Basic abc":    "",
		"":             "",
		"Bearer":       "",
		"Bearer a b c": "a b c",
	} {
		if got := bearer(header); got != want {
			t.Errorf("bearer(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestGateHandlerRejectsBeforeReachingTheTools(t *testing.T) {
	reached := false
	handler := new(gate).authorized(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if w.Code != http.StatusUnauthorized || reached {
		t.Errorf("unauthenticated request: status %d, reached handler %v", w.Code, reached)
	}

	authenticated := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	authenticated.Header.Set("Authorization", "Bearer key")
	handler.ServeHTTP(httptest.NewRecorder(), authenticated)
	if !reached {
		t.Error("an authenticated request did not reach the handler")
	}
}

// ---------------------------------------------------------------------------
// A stand-in executor
// ---------------------------------------------------------------------------

// fakeExecutor serves the executor's HTTP contract over TCP against a temp
// directory. The real executor is a separate module in this repo and
// cannot be imported; what is reproduced here is its documented API, which
// is the part mcp-server actually depends on.
func fakeExecutor(t *testing.T) (*executorClient, string) {
	t.Helper()
	dir := t.TempDir()

	resolve := func(p string) (string, bool) {
		if !filepath.IsAbs(p) {
			p = filepath.Join("/workspace", p)
		}
		rel, err := filepath.Rel("/workspace", p)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", false
		}
		return filepath.Join(dir, rel), true
	}
	fail := func(w http.ResponseWriter, status int, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/exec", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command string `json:"command"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		cmd := exec.Command("/bin/sh", "-c", req.Command)
		cmd.Dir = dir
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if !strings.Contains(err.Error(), "exit status") {
				fail(w, http.StatusInternalServerError, err.Error())
				return
			}
			if e, ok := err.(*exec.ExitError); ok {
				exitErr = e
				code = exitErr.ExitCode()
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"stdout": stdout.String(), "stderr": stderr.String(), "exit_code": code})
	})
	mux.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path string `json:"path"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		path, ok := resolve(req.Path)
		if !ok {
			fail(w, http.StatusBadRequest, "path escapes the workspace")
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fail(w, http.StatusNotFound, "file not found: "+req.Path)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"path": req.Path, "contents": base64.StdEncoding.EncodeToString(data)})
	})
	mux.HandleFunc("/write", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path     string `json:"path"`
			Contents string `json:"contents"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		path, ok := resolve(req.Path)
		if !ok {
			fail(w, http.StatusBadRequest, "path escapes the workspace")
			return
		}
		data, err := base64.StdEncoding.DecodeString(req.Contents)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalid base64 contents")
			return
		}
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"path": req.Path, "size": len(data)})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &executorClient{url: server.URL, http: server.Client()}, dir
}

// ---------------------------------------------------------------------------
// End to end, over the router's own MCP client
// ---------------------------------------------------------------------------

// keyTransport is the router's sandboxRoundTripper: the derived key, and
// nothing else.
type keyTransport struct{ key string }

func (k keyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header.Set("Authorization", "Bearer "+k.key)
	return http.DefaultTransport.RoundTrip(cloned)
}

// startSandbox starts the sandbox's real HTTP surface — gate and all —
// over a stand-in executor, and returns the MCP endpoint plus the
// workspace directory behind it.
func startSandbox(t *testing.T) (endpoint, dir string) {
	t.Helper()
	ex, dir := fakeExecutor(t)

	server := mcp.NewServer(&mcp.Implementation{Name: "confidential-agent-sandbox", Version: "v1"}, nil)
	addTools(server, ex)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		JSONResponse:               true,
		DisableLocalhostProtection: true,
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", new(gate).authorized(handler))
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	return httpServer.URL + "/mcp", dir
}

// dial opens a session the way confidential-model-router does: go-sdk
// streamable transport, derived key on every request. If these tests
// pass, the router can talk to this workload.
func dial(t *testing.T, endpoint, key string) (*mcp.ClientSession, error) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "router-tool-runtime", Version: "v1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: keyTransport{key: key}},
	}, nil)
	if err == nil {
		t.Cleanup(func() { session.Close() })
	}
	return session, err
}

func connect(t *testing.T, key string) (*mcp.ClientSession, string) {
	t.Helper()
	endpoint, dir := startSandbox(t)
	session, err := dial(t, endpoint, key)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return session, dir
}

func call(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var b strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	if result.IsError {
		t.Fatalf("%s returned a tool error: %s", name, b.String())
	}
	return b.String()
}

// callErr returns the text of a call the model is expected to get wrong.
func callErr(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error %v, want a tool error the model can read", name, err)
	}
	if !result.IsError {
		t.Fatalf("%s succeeded, want a tool error", name)
	}
	var b strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// TestAdvertisedTools pins the six names the router's prompt tells the
// model to use. Renaming one here silently breaks that prompt.
func TestAdvertisedTools(t *testing.T) {
	session, _ := connect(t, "derived-key")
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	found := map[string]bool{}
	for _, tool := range listed.Tools {
		found[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("tool %q has no description", tool.Name)
		}
		// The schema arrives as decoded JSON; the model needs it to
		// be an object schema with the tool's arguments on it.
		schema, _ := tool.InputSchema.(map[string]any)
		if schema["type"] != "object" || schema["properties"] == nil {
			t.Errorf("tool %q input schema = %v, want an object schema with properties", tool.Name, tool.InputSchema)
		}
	}
	for _, want := range []string{"shell", "view", "present", "str_replace", "create", "insert"} {
		if !found[want] {
			t.Errorf("the sandbox does not advertise %q", want)
		}
	}
	if len(listed.Tools) != 6 {
		t.Errorf("advertised %d tools, want exactly the six the profile expects", len(listed.Tools))
	}
}

func TestWrongKeyCannotReachTheTools(t *testing.T) {
	endpoint, _ := startSandbox(t)
	owner, err := dial(t, endpoint, "the-owners-key")
	if err != nil {
		t.Fatalf("the owner could not connect: %v", err)
	}
	call(t, owner, "shell", map[string]any{"command": "true"})

	if _, err := dial(t, endpoint, "someone-elses-key"); err == nil {
		t.Fatal("a client with the wrong key opened a session on an occupied sandbox")
	}
	// The rightful owner is unaffected by the attempt.
	call(t, owner, "shell", map[string]any{"command": "true"})
}

func TestShell(t *testing.T) {
	session, dir := connect(t, "k")
	out := call(t, session, "shell", map[string]any{"command": "echo hello > greeting.txt; echo done; echo oops >&2"})
	if !strings.Contains(out, "done") || !strings.Contains(out, "oops") || !strings.Contains(out, "exit_code: 0") {
		t.Errorf("shell output = %q", out)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "greeting.txt")); err != nil || string(data) != "hello\n" {
		t.Errorf("the command did not run in the workspace: %q (%v)", data, err)
	}

	out = call(t, session, "shell", map[string]any{"command": "exit 7"})
	if !strings.Contains(out, "exit_code: 7") {
		t.Errorf("shell output = %q, want the command's exit code", out)
	}
	if msg := callErr(t, session, "shell", map[string]any{"command": "   "}); !strings.Contains(msg, "required") {
		t.Errorf("empty command error = %q", msg)
	}
}

func TestEditingFlow(t *testing.T) {
	session, dir := connect(t, "k")

	call(t, session, "create", map[string]any{"path": "notes.md", "file_text": "one\ntwo\nthree\n"})
	if msg := callErr(t, session, "create", map[string]any{"path": "notes.md", "file_text": "again"}); !strings.Contains(msg, "already exists") {
		t.Errorf("recreate error = %q", msg)
	}

	view := call(t, session, "view", map[string]any{"path": "notes.md"})
	if !strings.Contains(view, "     1\tone") || !strings.Contains(view, "     3\tthree") {
		t.Errorf("view = %q, want numbered lines", view)
	}
	if ranged := call(t, session, "view", map[string]any{"path": "notes.md", "view_range": []any{2, 2}}); !strings.Contains(ranged, "two") || strings.Contains(ranged, "three") {
		t.Errorf("ranged view = %q", ranged)
	}
	// A range past the end of the file is clamped, not refused.
	if ranged := call(t, session, "view", map[string]any{"path": "notes.md", "view_range": []any{1, 900}}); !strings.Contains(ranged, "three") {
		t.Errorf("clamped view = %q", ranged)
	}

	call(t, session, "str_replace", map[string]any{"path": "notes.md", "old_str": "two", "new_str": "TWO"})
	call(t, session, "insert", map[string]any{"path": "notes.md", "line_number": 0, "text": "zero"})
	data, err := os.ReadFile(filepath.Join(dir, "notes.md"))
	if err != nil || string(data) != "zero\none\nTWO\nthree\n" {
		t.Errorf("file after edits = %q (%v)", data, err)
	}

	// An old_str that is not unique must fail rather than pick one.
	call(t, session, "create", map[string]any{"path": "dup.txt", "file_text": "x\nx\n"})
	if msg := callErr(t, session, "str_replace", map[string]any{"path": "dup.txt", "old_str": "x", "new_str": "y"}); !strings.Contains(msg, "appears 2 times") {
		t.Errorf("ambiguous str_replace error = %q", msg)
	}
	if msg := callErr(t, session, "str_replace", map[string]any{"path": "dup.txt", "old_str": "nope", "new_str": "y"}); !strings.Contains(msg, "not found") {
		t.Errorf("missing old_str error = %q", msg)
	}
	if msg := callErr(t, session, "insert", map[string]any{"path": "dup.txt", "line_number": 99, "text": "y"}); !strings.Contains(msg, "out of range") {
		t.Errorf("insert range error = %q", msg)
	}
}

// TestMissingFileIsAToolError: the model asks for files that do not exist
// all the time. That has to come back as a readable tool error naming the
// path, not as a protocol failure that kills the turn.
func TestMissingFileIsAToolError(t *testing.T) {
	session, _ := connect(t, "k")
	for _, tool := range []string{"view", "present"} {
		if msg := callErr(t, session, tool, map[string]any{"path": "absent.txt"}); !strings.Contains(msg, "absent.txt") {
			t.Errorf("%s error = %q, want the path named", tool, msg)
		}
	}
}

func TestPresentRendersACodeBlock(t *testing.T) {
	session, _ := connect(t, "k")
	call(t, session, "create", map[string]any{"path": "app.py", "file_text": "print('hi')\n"})
	out := call(t, session, "present", map[string]any{"path": "app.py"})
	if out != "```python\nprint('hi')\n```" {
		t.Errorf("present = %q, want a python-tagged fenced block", out)
	}

	// A markdown file with its own fences must not break out of the one
	// present wraps it in — the router emits this text straight into the
	// chat, so a broken fence renders as garbage for the user.
	call(t, session, "create", map[string]any{"path": "doc.md", "file_text": "text\n```js\ncode\n```\n"})
	out = call(t, session, "present", map[string]any{"path": "doc.md"})
	if !strings.HasPrefix(out, "````markdown\n") || !strings.HasSuffix(out, "\n````") {
		t.Errorf("present of nested fences = %q", out)
	}
}

func TestToolOutputIsBounded(t *testing.T) {
	session, _ := connect(t, "k")
	big := strings.Repeat("a", maxToolBytes+4096)
	call(t, session, "create", map[string]any{"path": "big.txt", "file_text": big})
	out := call(t, session, "view", map[string]any{"path": "big.txt"})
	if len(out) > maxToolBytes+128 {
		t.Errorf("view returned %d bytes, want it capped near %d", len(out), maxToolBytes)
	}
	if !strings.Contains(out, "[truncated:") {
		t.Error("truncated tool output did not say it was truncated")
	}
}

func TestInferLanguage(t *testing.T) {
	for path, want := range map[string]string{
		"a.py": "python", "a.GO": "go", "Dockerfile": "dockerfile",
		"src/Makefile": "makefile", "a.unknown": "", "noext": "",
	} {
		if got := inferLanguage(path); got != want {
			t.Errorf("inferLanguage(%q) = %q, want %q", path, got, want)
		}
	}
}
