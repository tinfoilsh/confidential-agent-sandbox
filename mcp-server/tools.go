package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The six tools the router's agent-sandbox profile expects, by name:
// shell, view, present, str_replace, create, insert. The names and the
// present rendering are a contract with confidential-model-router — its
// prompt names these tools, and it re-emits a present result verbatim as
// assistant content — so neither can be renamed on this side alone.

// maxToolBytes caps the text of a single tool result. The executor
// already bounds command output and file size; this is the backstop that
// keeps one view of a large file from crowding out the conversation it
// was meant to inform.
const maxToolBytes = 256 << 10

type shellInput struct {
	Command string `json:"command" jsonschema:"the shell command to run"`
}

type pathInput struct {
	Path string `json:"path" jsonschema:"absolute or workspace-relative path to the file"`
	// ViewRange is [start, end], 1-indexed and inclusive.
	ViewRange []int `json:"view_range,omitempty" jsonschema:"optional [start_line, end_line], 1-indexed and inclusive; omit for the whole file"`
}

type replaceInput struct {
	Path   string `json:"path" jsonschema:"absolute or workspace-relative path to the file"`
	OldStr string `json:"old_str" jsonschema:"the exact string to replace; must appear exactly once in the file"`
	NewStr string `json:"new_str" jsonschema:"the replacement string"`
}

type createInput struct {
	Path     string `json:"path" jsonschema:"absolute or workspace-relative path for the new file"`
	FileText string `json:"file_text" jsonschema:"the full contents of the file to create"`
}

type insertInput struct {
	Path       string `json:"path" jsonschema:"absolute or workspace-relative path to the file"`
	LineNumber int    `json:"line_number" jsonschema:"insert after this line (0 inserts at the beginning of the file)"`
	Text       string `json:"text" jsonschema:"the text to insert"`
}

// addTools registers every tool against one executor. Handlers return
// plain errors for anything the model can fix — a missing file, an
// ambiguous old_str — and the SDK turns those into tool errors rather
// than protocol errors, so the model sees them and can try again.
func addTools(server *mcp.Server, ex *executorClient) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "shell",
		Description: "Run a shell command in the sandbox. The working directory is /workspace and the sandbox has no network access. " +
			"Returns stdout, stderr, and the exit code. Commands are killed after 120 seconds; each call starts a fresh shell, so cd and environment variables do not carry over between calls (files do).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in shellInput) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(in.Command) == "" {
			return nil, nil, fmt.Errorf("command is required")
		}
		result, err := ex.exec(ctx, in.Command)
		if err != nil {
			return nil, nil, err
		}
		var b strings.Builder
		if result.Stdout != "" {
			fmt.Fprintf(&b, "stdout:\n%s\n", result.Stdout)
		}
		if result.Stderr != "" {
			fmt.Fprintf(&b, "stderr:\n%s\n", result.Stderr)
		}
		fmt.Fprintf(&b, "exit_code: %d", result.ExitCode)
		return text(b.String()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "view",
		Description: "View a file's contents with line numbers. Returns the whole file, or just the given line range.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, any, error) {
		lines, start, end, err := readLines(ctx, ex, in)
		if err != nil {
			return nil, nil, err
		}
		var b strings.Builder
		for i := start; i <= end; i++ {
			fmt.Fprintf(&b, "%6d\t%s\n", i, lines[i-1])
		}
		return text(b.String()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "present",
		Description: "Show a file to the user. The file is rendered directly in the chat as a syntax-highlighted code block, exactly as if you had pasted it inline. " +
			"You will receive the file's contents back as the tool result so you can keep working with it, but the user has ALREADY SEEN the full file by the time this tool returns. " +
			"After calling present, do NOT re-paste, restate, summarize, or quote the file's contents in your reply — the user is looking at it. " +
			"Brief commentary about the file (e.g. \"here's foo.py — note the bug on line 12\") is fine; reproducing any portion of the file is not. " +
			"Prefer present over pasting file contents in your response. Same arguments as view.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, any, error) {
		lines, start, end, err := readLines(ctx, ex, in)
		if err != nil {
			return nil, nil, err
		}
		body := strings.Join(lines[start-1:end], "\n")
		fence := longestFence(body)
		return text(fmt.Sprintf("%s%s\n%s\n%s", fence, inferLanguage(in.Path), body, fence)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "str_replace",
		Description: "Replace an exact string in a file. old_str must appear exactly once in the file.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in replaceInput) (*mcp.CallToolResult, any, error) {
		contents, err := ex.readFile(ctx, in.Path)
		if err != nil {
			return nil, nil, fileError(in.Path, err)
		}
		switch count := strings.Count(contents, in.OldStr); count {
		case 1:
		case 0:
			return nil, nil, fmt.Errorf("old_str not found in %s", in.Path)
		default:
			return nil, nil, fmt.Errorf("old_str appears %d times in %s — include enough surrounding context to make it unique", count, in.Path)
		}
		if err := ex.writeFile(ctx, in.Path, strings.Replace(contents, in.OldStr, in.NewStr, 1)); err != nil {
			return nil, nil, err
		}
		return text(fmt.Sprintf("Replaced 1 occurrence in %s", in.Path)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "create",
		Description: "Create a new file with the given contents. Fails if the file already exists — use str_replace or insert to change a file you already have.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in createInput) (*mcp.CallToolResult, any, error) {
		switch _, err := ex.readFile(ctx, in.Path); {
		case err == nil:
			return nil, nil, fmt.Errorf("file already exists: %s", in.Path)
		case !isNotExist(err):
			// Anything other than "no such file" — a directory, a path
			// that escapes the workspace — is the caller's answer.
			return nil, nil, fileError(in.Path, err)
		}
		if err := ex.writeFile(ctx, in.Path, in.FileText); err != nil {
			return nil, nil, err
		}
		return text("Created " + in.Path), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "insert",
		Description: "Insert text after a given line number in a file. Use line 0 to insert at the beginning.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in insertInput) (*mcp.CallToolResult, any, error) {
		contents, err := ex.readFile(ctx, in.Path)
		if err != nil {
			return nil, nil, fileError(in.Path, err)
		}
		lines := strings.Split(contents, "\n")
		if in.LineNumber < 0 || in.LineNumber > len(lines) {
			return nil, nil, fmt.Errorf("line_number %d out of range (%s has %d lines)", in.LineNumber, in.Path, len(lines))
		}
		updated := append([]string{}, lines[:in.LineNumber]...)
		updated = append(updated, in.Text)
		updated = append(updated, lines[in.LineNumber:]...)
		if err := ex.writeFile(ctx, in.Path, strings.Join(updated, "\n")); err != nil {
			return nil, nil, err
		}
		return text(fmt.Sprintf("Inserted text after line %d in %s", in.LineNumber, in.Path)), nil, nil
	})
}

// text builds a tool result, truncating anything past maxToolBytes.
func text(s string) *mcp.CallToolResult {
	if len(s) > maxToolBytes {
		s = s[:maxToolBytes] + fmt.Sprintf("\n[truncated: %d more bytes]", len(s)-maxToolBytes)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// readLines reads a file and resolves the optional view_range against it,
// clamping to the file rather than failing: a model that asks for lines
// 1-500 of a 30-line file wants the file, not an error.
func readLines(ctx context.Context, ex *executorClient, in pathInput) (lines []string, start, end int, err error) {
	contents, err := ex.readFile(ctx, in.Path)
	if err != nil {
		return nil, 0, 0, fileError(in.Path, err)
	}
	// Files normally end with a trailing newline, which would otherwise
	// show up as a final empty line.
	lines = strings.Split(strings.TrimSuffix(contents, "\n"), "\n")
	start, end = 1, len(lines)
	if len(in.ViewRange) == 2 {
		start, end = in.ViewRange[0], in.ViewRange[1]
	}
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		return nil, 0, 0, fmt.Errorf("invalid view_range: start %d is past end %d", start, end)
	}
	return lines, start, end, nil
}

// fileError names the path a read failed on. The executor's 404 carries
// no path, and "file not found" alone leaves the model guessing which of
// its arguments was wrong.
func fileError(path string, err error) error {
	if isNotExist(err) {
		return fmt.Errorf("file not found: %s", path)
	}
	return err
}

func isNotExist(err error) bool { return errors.Is(err, errNotExist) }

// extensionToLanguage maps file extensions to the language tag used in
// markdown fenced code blocks. Unknown extensions return "" so the fence
// renders without a language hint.
var extensionToLanguage = map[string]string{
	".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript",
	".tsx": "tsx", ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
	".swift": "swift", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp",
	".cxx": "cpp", ".hpp": "cpp", ".cs": "csharp", ".rb": "ruby", ".php": "php",
	".sh": "bash", ".bash": "bash", ".zsh": "bash", ".fish": "bash",
	".ps1": "powershell", ".sql": "sql", ".html": "html", ".htm": "html",
	".css": "css", ".scss": "scss", ".sass": "sass", ".less": "less",
	".json": "json", ".jsonc": "json", ".yaml": "yaml", ".yml": "yaml",
	".toml": "toml", ".xml": "xml", ".md": "markdown", ".markdown": "markdown",
	".tex": "latex", ".r": "r", ".lua": "lua", ".pl": "perl", ".scala": "scala",
	".clj": "clojure", ".ex": "elixir", ".exs": "elixir", ".erl": "erlang",
	".hs": "haskell", ".dart": "dart", ".vim": "vim", ".dockerfile": "dockerfile",
	".makefile": "makefile", ".cmake": "cmake", ".graphql": "graphql", ".proto": "protobuf",
}

// inferLanguage picks a markdown code-fence language from a path, falling
// back to filename matches before giving up.
func inferLanguage(path string) string {
	if lang, ok := extensionToLanguage[strings.ToLower(filepath.Ext(path))]; ok {
		return lang
	}
	switch strings.ToLower(filepath.Base(path)) {
	case "dockerfile":
		return "dockerfile"
	case "makefile", "gnumakefile":
		return "makefile"
	case "cmakelists.txt":
		return "cmake"
	}
	return ""
}

// longestFence returns a backtick fence longer than any run of backticks
// in the body, so a markdown file with its own code blocks cannot break
// out of the one present wraps it in.
func longestFence(body string) string {
	longest, run := 0, 0
	for _, r := range body {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	if longest < 2 {
		return "```"
	}
	return strings.Repeat("`", longest+1)
}
