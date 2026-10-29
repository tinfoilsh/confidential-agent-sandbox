package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// pollUntil polls a shell through the owner API until its output contains want or it closes.
func (h *harness) pollUntil(session string, cursor *float64, output *strings.Builder, want string) map[string]any {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		code, reply := h.call(h.owner, http.MethodPost, "/shell", map[string]any{"action": "poll", "id": session, "cursor": *cursor}, id(16), session, time.Now().UnixMilli())
		if code != http.StatusOK {
			h.t.Fatalf("poll: %d %v", code, reply)
		}
		data, _ := base64.StdEncoding.DecodeString(reply["data"].(string))
		output.Write(data)
		*cursor = reply["cursor"].(float64)
		if strings.Contains(output.String(), want) || reply["closed"] == true {
			return reply
		}
	}
	h.t.Fatalf("no %q in %q", want, output.String())
	return nil
}

func TestShellOverSealedOwnerAPI(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UnixMilli()
	code, opened := h.call(h.owner, http.MethodPost, "/shell", map[string]any{"action": "open", "cols": 80, "rows": 24}, id(16), "", now)
	if code != http.StatusOK {
		t.Fatalf("open: %d %v", code, opened)
	}
	session := opened["id"].(string)
	input := func(seq int, text, operation string) (int, map[string]any) {
		return h.call(h.owner, http.MethodPost, "/shell", map[string]any{"action": "input", "id": session, "seq": seq, "data": []byte(text)}, operation, session, now)
	}
	command := "printf 'mark%s\\n' 1\n"
	operation := id(16)
	if code, reply := input(0, command, operation); code != http.StatusOK || reply["accepted"] != float64(len(command)) {
		t.Fatalf("input: %d %v", code, reply)
	}
	// A retry returns the recorded count; a new operation cannot reuse the sequence.
	if code, reply := input(0, command, operation); code != http.StatusOK || reply["accepted"] != float64(len(command)) {
		t.Fatalf("retry: %d %v", code, reply)
	}
	if code, reply := input(0, command, id(16)); code != http.StatusConflict {
		t.Fatalf("reused sequence: %d %v", code, reply)
	}
	var cursor float64
	var output strings.Builder
	h.pollUntil(session, &cursor, &output, "mark1")
	if code, reply := h.call(h.owner, http.MethodPost, "/shell", map[string]any{"action": "resize", "id": session, "cols": 100, "rows": 30}, id(16), session, now); code != http.StatusOK {
		t.Fatalf("resize: %d %v", code, reply)
	}
	input(1, "stty size; exit 3\n", id(16))
	closed := h.pollUntil(session, &cursor, &output, "\x00")
	if closed["closed"] != true || closed["exit_code"] != 3.0 || strings.Count(output.String(), "mark1") != 1 || !strings.Contains(output.String(), "30 100") {
		t.Fatalf("end %v after %q", closed, output.String())
	}
	// The signed session must name the shell it addresses.
	if code, reply := h.call(h.owner, http.MethodPost, "/shell", map[string]any{"action": "poll", "id": session}, id(16), id(16), now); code != http.StatusBadRequest || reply["error"] != "malformed" {
		t.Fatalf("other session: %d %v", code, reply)
	}
	if code, _ := h.call(h.owner, http.MethodPost, "/shell", map[string]any{"action": "close", "id": session}, id(16), session, now); code != http.StatusOK {
		t.Fatal("close")
	}
	if code, _ := h.call(h.owner, http.MethodPost, "/shell", map[string]any{"action": "poll", "id": session}, id(16), session, now); code != http.StatusNotFound {
		t.Fatalf("closed session: %d", code)
	}

	// A short write into a shell that stopped reading is recorded once; its retry gets
	// the same count instead of writing that prefix again.
	defer func(timeout time.Duration) { shellWriteTimeout = timeout }(shellWriteTimeout)
	shellWriteTimeout = 200 * time.Millisecond
	h.server.shells.command = func() *exec.Cmd { return exec.Command("/bin/sh", "-c", "sleep 30") }
	_, opened = h.call(h.owner, http.MethodPost, "/shell", map[string]any{"action": "open", "cols": 80, "rows": 24}, id(16), "", now)
	session = opened["id"].(string)
	chunk := strings.Repeat("x\n", maxShellInput/2)
	var reply map[string]any
	var stalled string
	seq := 0
	for ; seq < 64; seq++ {
		stalled = id(16)
		if _, reply = input(seq, chunk, stalled); reply["closed"] == true {
			break
		}
	}
	if reply["closed"] != true || reply["accepted"].(float64) >= float64(len(chunk)) || reply["id"] != session {
		t.Fatalf("no short write: %v", reply)
	}
	if _, retry := input(seq, chunk, stalled); retry["accepted"] != reply["accepted"] || retry["closed"] != true {
		t.Fatalf("retry of the short write: %v", retry)
	}
}

func TestShellLimits(t *testing.T) {
	ctx := context.Background()
	locked := errors.New("locked")
	sh := &shells{command: func() *exec.Cmd { return exec.Command("/bin/sh", "-c", "sleep 30") }, ready: func() error { return locked }}
	if _, err := sh.serve(ctx, shellInput{Action: "open", Cols: 80, Rows: 24}); err != locked {
		t.Fatalf("open before the workspace runs: %v", err)
	}
	sh.ready = func() error { return nil }
	for _, size := range [][2]uint32{{0, 24}, {80, 1001}} {
		if _, err := sh.serve(ctx, shellInput{Action: "open", Cols: size[0], Rows: size[1]}); err == nil {
			t.Fatalf("opened %v", size)
		}
	}
	var ids []string
	for range maxShellSessions {
		reply, err := sh.serve(ctx, shellInput{Action: "open", Cols: 80, Rows: 24})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, reply.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			sh.serve(ctx, shellInput{Action: "close", ID: id})
		}
	})
	if _, err := sh.serve(ctx, shellInput{Action: "open", Cols: 80, Rows: 24}); err == nil {
		t.Fatal("opened more than the session limit")
	}
	sh.serve(ctx, shellInput{Action: "close", ID: ids[1]})
	reopened, err := sh.serve(ctx, shellInput{Action: "open", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("closing did not release a session: %v", err)
	}
	ids[1] = reopened.ID
	if _, err := sh.serve(ctx, shellInput{Action: "input", ID: ids[0], Data: make([]byte, maxShellInput+1)}); err == nil {
		t.Fatal("accepted oversized input")
	}

	// The shell never reads, so its terminal fills and a write stops part way, promptly,
	// including after a resize.
	if _, err := sh.serve(ctx, shellInput{Action: "resize", ID: ids[0], Cols: 120, Rows: 40}); err != nil {
		t.Fatal(err)
	}
	defer func(timeout time.Duration) { shellWriteTimeout = timeout }(shellWriteTimeout)
	shellWriteTimeout = 200 * time.Millisecond
	chunk := bytes.Repeat([]byte("x\n"), maxShellInput/2)
	var partial shellReply
	for seq := uint64(0); seq < 64 && !partial.Closed; seq++ {
		started := time.Now()
		reply, err := sh.serve(ctx, shellInput{Action: "input", ID: ids[0], Seq: seq, Data: chunk})
		if err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed > 5*shellWriteTimeout {
			t.Fatalf("a stalled write took %v", elapsed)
		}
		partial = reply
	}
	if !partial.Closed || *partial.Accepted >= len(chunk) || partial.ID != ids[0] {
		t.Fatalf("no short write: %+v", partial)
	}
	if _, err := sh.serve(ctx, shellInput{Action: "input", ID: ids[0], Seq: 64, Data: chunk}); err == nil {
		t.Fatal("wrote to a session ended by a short write")
	}
	if reply, err := sh.serve(ctx, shellInput{Action: "poll", ID: ids[0]}); err != nil || !reply.Closed {
		t.Fatalf("poll after a short write: %+v %v", reply, err)
	}
}
