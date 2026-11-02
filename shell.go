package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

const (
	// maxShellSessions bounds the shells open at once.
	maxShellSessions = 8
	// maxShellChunk bounds the output one message carries.
	maxShellChunk = 64 << 10

	shellTerminal   = "xterm-256color"
	maxShellInput   = 64 << 10
	maxTerminalSize = 1000
)

// shellWriteTimeout bounds how long a shell may leave its input unread.
var shellWriteTimeout = 10 * time.Second

type shellInput struct {
	Input  []byte `json:"input"`
	Resize *struct {
		Cols uint32 `json:"cols"`
		Rows uint32 `json:"rows"`
	} `json:"resize"`
}

// shells serves the measured owner's terminals, each for as long as its socket.
type shells struct {
	// command starts a login shell as the sandbox user.
	command func() *exec.Cmd
	// ready refuses shells until the workspace runs under systemd.
	ready func() error

	open atomic.Int32
}

// serve streams one shell: input and resizes in, output and then its exit code out. A
// closed socket, or a shell that stops reading its input, kills the shell.
func (sh *shells) serve(ctx context.Context, c *Channel, cols, rows uint32) {
	defer sh.open.Add(-1)
	terminal, cmd, err := sh.start(cols, rows)
	if err != nil {
		c.Conn.Close(websocket.StatusInternalError, err.Error())
		return
	}
	go func() {
		for {
			var in shellInput
			message, err := c.Read(ctx, maxShellInput)
			if err == nil {
				err = json.Unmarshal(message, &in)
			}
			if err == nil && in.Resize != nil && validTerminal(in.Resize.Cols, in.Resize.Rows) {
				err = control(terminal, func(fd int) error {
					return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(in.Resize.Rows), Col: uint16(in.Resize.Cols)})
				})
			}
			if err == nil && len(in.Input) > 0 {
				if err = terminal.SetWriteDeadline(time.Now().Add(shellWriteTimeout)); err == nil {
					_, err = terminal.Write(in.Input)
				}
			}
			if err != nil {
				terminal.Close()
				cmd.Process.Kill()
				return
			}
		}
	}()
	buffer := make([]byte, maxShellChunk)
	for n, err := terminal.Read(buffer); err == nil; n, err = terminal.Read(buffer) {
		output, _ := json.Marshal(map[string][]byte{"output": buffer[:n]})
		if c.Write(ctx, output) != nil {
			break
		}
	}
	terminal.Close()
	cmd.Process.Kill()
	cmd.Wait()
	exit := map[string]*int{"exit": nil}
	if code := cmd.ProcessState.ExitCode(); code >= 0 {
		exit["exit"] = &code
	}
	message, _ := json.Marshal(exit)
	c.Write(ctx, message)
	c.Conn.Close(websocket.StatusNormalClosure, "")
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

// start counts a shell, which its caller releases, and runs it as a login shell on a PTY
// once the workspace is unlocked and running.
func (sh *shells) start(cols, rows uint32) (*os.File, *exec.Cmd, error) {
	if sh.open.Add(1) > maxShellSessions {
		return nil, nil, ownerError{fmt.Sprintf("at most %d shells can be open; close one first", maxShellSessions), http.StatusServiceUnavailable}
	}
	if !validTerminal(cols, rows) {
		return nil, nil, fmt.Errorf("terminal size must be 1-%d columns and rows", maxTerminalSize)
	}
	if err := sh.ready(); err != nil {
		return nil, nil, err
	}
	cmd := sh.command()
	cmd.Env = append(cmd.Env, "TERM="+shellTerminal)
	terminal, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	if err != nil {
		return nil, nil, err
	}
	// The pty helpers leave the descriptor blocking; the poller needs it nonblocking so
	// write deadlines and Close interrupt a shell that stops reading.
	if err := control(terminal, func(fd int) error { return unix.SetNonblock(fd, true) }); err != nil {
		terminal.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, nil, err
	}
	return terminal, cmd, nil
}
