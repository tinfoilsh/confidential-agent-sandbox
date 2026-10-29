package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

const (
	// maxShellSessions bounds the shells open at once.
	maxShellSessions = 8
	// maxShellChunk bounds the output one poll returns.
	maxShellChunk = 64 << 10
	// maxShellBuffer bounds the output a shell holds until polls acknowledge it.
	maxShellBuffer = 1 << 20

	shellTerminal    = "xterm-256color"
	maxShellInput    = 64 << 10
	maxTerminalSize  = 1000
	shellPollTimeout = 25 * time.Second
	shellIdleTimeout = 2 * time.Minute
)

// shellWriteTimeout bounds how long a shell may leave its input unread.
var shellWriteTimeout = 10 * time.Second

var (
	errShellGone     = ownerError{"the shell session ended or does not exist", http.StatusNotFound}
	errShellSequence = ownerError{"shell input is out of sequence", http.StatusConflict}
)

type shellInput struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Cursor uint64 `json:"cursor"`
	Data   []byte `json:"data"`
	Cols   uint32 `json:"cols"`
	Rows   uint32 `json:"rows"`
	Seq    uint64 `json:"seq"`
}

type shellReply struct {
	ID       string `json:"id"`
	Data     []byte `json:"data"`
	Cursor   uint64 `json:"cursor"`
	Closed   bool   `json:"closed"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Accepted *int   `json:"accepted,omitempty"`
}

// shells serves the measured owner's terminals; owner and instance are fixed per boot,
// so the session ID completes the binding.
type shells struct {
	// command starts a login shell as the sandbox user.
	command func() *exec.Cmd
	// ready refuses shells until the workspace runs under systemd.
	ready func() error

	mu       sync.Mutex
	sessions map[string]*shellSession
}

// shellSession is one owner terminal. Output stays buffered until a poll acknowledges
// it, and a full buffer pauses the shell rather than dropping output.
type shellSession struct {
	pty  *os.File
	cmd  *exec.Cmd
	idle *time.Timer

	input   sync.Mutex
	nextSeq uint64

	mu      sync.Mutex
	changed chan struct{} // Closed and replaced on every change.
	output  []byte
	start   uint64 // The cursor of output[0].
	ended   bool
	exit    *int
}

func (sh *shells) serve(ctx context.Context, in shellInput) (shellReply, error) {
	switch in.Action {
	case "open":
		return sh.open(in)
	case "poll", "input", "resize", "close":
	default:
		return shellReply{}, fmt.Errorf("unknown shell action %q", in.Action)
	}
	sh.mu.Lock()
	s := sh.sessions[in.ID]
	sh.mu.Unlock()
	if s == nil {
		return shellReply{}, errShellGone
	}
	s.idle.Reset(shellIdleTimeout)
	reply := shellReply{ID: in.ID, Data: []byte{}}
	switch in.Action {
	case "poll":
		// An ended session stays until closed or idle, so a lost final reply can be polled again.
		polled, err := s.poll(ctx, in.Cursor)
		s.idle.Reset(shellIdleTimeout)
		polled.ID = in.ID
		return polled, err
	case "close":
		sh.drop(in.ID, s)
		reply.Closed = true
		return reply, nil
	case "resize":
		if !validTerminal(in.Cols, in.Rows) {
			return shellReply{}, fmt.Errorf("terminal size must be 1-%d columns and rows", maxTerminalSize)
		}
		return reply, control(s.pty, func(fd int) error {
			return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(in.Rows), Col: uint16(in.Cols)})
		})
	}
	if len(in.Data) > maxShellInput {
		return shellReply{}, fmt.Errorf("shell input is limited to %d bytes per call", maxShellInput)
	}
	reply, err := s.write(in.Seq, in.Data)
	reply.ID = in.ID
	return reply, err
}

// control runs fn on a PTY's descriptor without File.Fd, which would make it blocking.
func control(f *os.File, fn func(fd int) error) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var fnErr error
	if err := raw.Control(func(fd uintptr) { fnErr = fn(int(fd)) }); err != nil {
		return err
	}
	return fnErr
}

func validTerminal(cols, rows uint32) bool {
	return cols > 0 && rows > 0 && cols <= maxTerminalSize && rows <= maxTerminalSize
}

// open starts a login shell on a PTY once the workspace is unlocked and running.
func (sh *shells) open(in shellInput) (shellReply, error) {
	if !validTerminal(in.Cols, in.Rows) {
		return shellReply{}, fmt.Errorf("terminal size must be 1-%d columns and rows", maxTerminalSize)
	}
	if err := sh.ready(); err != nil {
		return shellReply{}, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	name := base64.RawURLEncoding.EncodeToString(id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if len(sh.sessions) >= maxShellSessions {
		return shellReply{}, ownerError{fmt.Sprintf("at most %d shells can be open; close one first", maxShellSessions), http.StatusServiceUnavailable}
	}
	cmd := sh.command()
	cmd.Env = append(cmd.Env, "TERM="+shellTerminal)
	terminal, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(in.Rows), Cols: uint16(in.Cols)})
	if err != nil {
		return shellReply{}, err
	}
	// The pty helpers leave the descriptor blocking; the poller needs it nonblocking so
	// write deadlines and Close interrupt a shell that stops reading.
	if err := control(terminal, func(fd int) error { return unix.SetNonblock(fd, true) }); err != nil {
		terminal.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return shellReply{}, err
	}
	s := &shellSession{pty: terminal, cmd: cmd, changed: make(chan struct{})}
	s.idle = time.AfterFunc(shellIdleTimeout, func() { sh.drop(name, s) })
	if sh.sessions == nil {
		sh.sessions = map[string]*shellSession{}
	}
	sh.sessions[name] = s
	go s.relay()
	return shellReply{ID: name, Data: []byte{}}, nil
}

func (sh *shells) drop(id string, s *shellSession) {
	sh.mu.Lock()
	if sh.sessions[id] == s {
		delete(sh.sessions, id)
	}
	sh.mu.Unlock()
	s.close()
}

// write accepts input only in sequence. A short write ends the session, and its count is
// the reply a retry receives, so no prefix of that input is ever written twice.
func (s *shellSession) write(seq uint64, data []byte) (shellReply, error) {
	s.input.Lock()
	defer s.input.Unlock()
	if seq != s.nextSeq {
		return shellReply{}, errShellSequence
	}
	s.mu.Lock()
	ended := s.ended
	s.mu.Unlock()
	if ended {
		return shellReply{}, errShellGone
	}
	s.nextSeq++
	n, err := 0, s.pty.SetWriteDeadline(time.Now().Add(shellWriteTimeout))
	if err == nil {
		n, err = s.pty.Write(data)
	}
	reply := shellReply{Data: []byte{}, Accepted: &n}
	if err != nil {
		// A shell that stops reading cannot hold the request; it is closed instead.
		s.close()
		reply.Closed = true
	}
	return reply, nil
}

// signal wakes waiters; the caller holds mu.
func (s *shellSession) signal() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *shellSession) close() {
	s.mu.Lock()
	s.ended = true
	s.signal()
	s.mu.Unlock()
	s.idle.Stop()
	s.pty.Close()
	s.cmd.Process.Kill()
}

func (s *shellSession) relay() {
	buffer := make([]byte, maxShellChunk)
	for {
		n, err := s.pty.Read(buffer)
		if n > 0 && !s.append(buffer[:n]) || err != nil {
			break
		}
	}
	err := s.cmd.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	var exit *exec.ExitError
	if !s.ended && err == nil {
		s.exit = new(int)
	} else if !s.ended && errors.As(err, &exit) {
		code := exit.ExitCode()
		s.exit = &code
	}
	s.ended = true
	s.signal()
}

func (s *shellSession) append(p []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Backpressure bounds unread output.
	for len(s.output)+len(p) > maxShellBuffer && !s.ended {
		changed := s.changed
		s.mu.Unlock()
		<-changed
		s.mu.Lock()
	}
	if s.ended {
		return false
	}
	s.output = append(s.output, p...)
	s.signal()
	return true
}

// poll acknowledges output before cursor, then waits for more output, the end, or a timeout.
func (s *shellSession) poll(ctx context.Context, cursor uint64) (shellReply, error) {
	timeout := time.NewTimer(shellPollTimeout)
	defer timeout.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	if cursor < s.start || cursor-s.start > uint64(len(s.output)) {
		return shellReply{}, errors.New("shell cursor is outside the unacknowledged output")
	}
	// Cursor advances acknowledge consumption.
	if cursor > s.start {
		s.output = s.output[cursor-s.start:]
		s.start = cursor
		s.signal()
	}
	for wait := true; wait && len(s.output) == 0 && !s.ended; {
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			wait = false
		case <-timeout.C:
			wait = false
		}
		s.mu.Lock()
	}
	data := append([]byte{}, s.output[:min(len(s.output), maxShellChunk)]...)
	reply := shellReply{Data: data, Cursor: cursor + uint64(len(data))}
	if s.ended && len(data) == len(s.output) {
		reply.Closed, reply.ExitCode = true, s.exit
	}
	return reply, nil
}
