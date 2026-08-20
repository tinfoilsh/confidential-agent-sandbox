package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// executorSocket is the shared-volume socket the executor listens on. It
// is the only way out of this container into the workspace, and the only
// way anything reaches the shell.
const executorSocket = "/run/execsock/exec.sock"

// executorURL's host is ignored by the unix dialer but http.NewRequest
// still wants a syntactically valid URL.
const executorURL = "http://executor"

// errNotExist is the executor's 404 in error form, so create can ask
// "does this file exist?" with a read instead of another endpoint.
var errNotExist = errors.New("file not found")

// maxExecutorResponseBytes bounds one reply from the executor. A /read of
// a file at the executor's 8 MB ceiling arrives base64-encoded inside a
// JSON envelope, so the limit sits well above that; it exists to stop a
// malfunctioning executor from exhausting this container's memory, not to
// shape anything a caller sees.
const maxExecutorResponseBytes = 24 << 20

type executorClient struct {
	url  string
	http *http.Client
}

func newExecutorClient(socket string) *executorClient {
	return &executorClient{
		url: executorURL,
		http: &http.Client{
			// Above the executor's own 120s command timeout, so a
			// long-running shell command ends with the executor's
			// truncated output rather than a transport error that
			// tells the model nothing.
			Timeout: 150 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

type execResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

func (e *executorClient) exec(ctx context.Context, command string) (execResult, error) {
	var out execResult
	err := e.call(ctx, "/exec", map[string]string{"command": command}, &out)
	return out, err
}

// readFile returns a file's contents, or errNotExist if there is none.
func (e *executorClient) readFile(ctx context.Context, path string) (string, error) {
	var out struct {
		Contents string `json:"contents"`
	}
	if err := e.call(ctx, "/read", map[string]string{"path": path}, &out); err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(out.Contents)
	if err != nil {
		return "", fmt.Errorf("executor returned undecodable contents: %w", err)
	}
	return string(data), nil
}

func (e *executorClient) writeFile(ctx context.Context, path, contents string) error {
	return e.call(ctx, "/write", map[string]string{
		"path":     path,
		"contents": base64.StdEncoding.EncodeToString([]byte(contents)),
	}, nil)
}

func (e *executorClient) healthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// call posts a JSON request and decodes the reply. The executor reports
// tool-level problems ("file not found", "path escapes") as {"error"} with
// a 4xx; those become plain errors here, which the MCP layer hands back to
// the model as a tool error it can correct.
func (e *executorClient) call(ctx context.Context, path string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("sandbox executor unavailable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxExecutorResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &failure)
		if failure.Error == "" {
			failure.Error = fmt.Sprintf("executor returned status %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusNotFound {
			// The path is added back by whichever tool asked, so the
			// executor's wording is not worth keeping here.
			return errNotExist
		}
		return errors.New(failure.Error)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}
