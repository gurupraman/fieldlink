// Package fs implements the fs.read and fs.list capabilities (design.md §5)
// as the read_file and list_directory MCP tools. Both are read-only: this
// package contains no write, create, or delete path, on purpose.
package fs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/getsetai/fieldlink/internal/policy"
)

const defaultMaxBytes int64 = 1 << 20 // 1 MiB

// Executor implements read_file and list_directory. Every call is checked
// against Policy first; Executor never decides on its own that a path is
// permitted.
type Executor struct {
	Policy policy.Engine
}

type ReadFileInput struct {
	Path     string `json:"path" jsonschema:"path to the file to read"`
	MaxBytes int64  `json:"max_bytes,omitempty" jsonschema:"maximum bytes to return before falling back to a digest; defaults to 1048576"`
}

type ReadFileOutput struct {
	Path       string `json:"path"`
	Content    string `json:"content,omitempty"`
	SizeBytes  int64  `json:"size_bytes"`
	Truncated  bool   `json:"truncated"`
	Digest     string `json:"digest,omitempty"`
	ModifiedAt string `json:"modified_at"`
}

func (e *Executor) ReadFile(ctx context.Context, _ *mcp.CallToolRequest, in ReadFileInput) (*mcp.CallToolResult, ReadFileOutput, error) {
	if in.Path == "" {
		return denied("path is required"), ReadFileOutput{}, nil
	}
	maxBytes := in.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}

	resolved, err := resolveSafe(in.Path)
	if err != nil {
		return denied("path could not be resolved"), ReadFileOutput{}, nil
	}

	decision := e.Policy.Authorize(ctx, "fs.read", map[string]any{
		"path":      resolved,
		"max_bytes": maxBytes,
	})
	if !decision.Allowed {
		return denied(decision.Reason), ReadFileOutput{}, nil
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return denied("file not found or not readable"), ReadFileOutput{}, nil
	}
	if info.IsDir() {
		return denied("path is a directory, not a file"), ReadFileOutput{}, nil
	}

	f, err := os.Open(resolved)
	if err != nil {
		return denied("file not found or not readable"), ReadFileOutput{}, nil
	}
	defer f.Close()

	if info.Size() > maxBytes {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return denied("file could not be read"), ReadFileOutput{}, nil
		}
		out := ReadFileOutput{
			Path:       in.Path,
			SizeBytes:  info.Size(),
			Truncated:  true,
			Digest:     fmt.Sprintf("sha256:%x", h.Sum(nil)),
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
				"%s is %d bytes, exceeding max_bytes=%d; returning digest only", in.Path, info.Size(), maxBytes)}},
		}, out, nil
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return denied("file could not be read"), ReadFileOutput{}, nil
	}

	out := ReadFileOutput{
		Path:       in.Path,
		Content:    string(data),
		SizeBytes:  info.Size(),
		ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
	}
	return nil, out, nil
}

type ListDirectoryInput struct {
	Path      string `json:"path" jsonschema:"directory to list"`
	Glob      string `json:"glob,omitempty" jsonschema:"optional glob pattern to filter entry names, e.g. *.csv"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"list nested directories as well"`
}

type DirEntry struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"is_dir"`
	SizeBytes  int64  `json:"size_bytes"`
	ModifiedAt string `json:"modified_at"`
}

type ListDirectoryOutput struct {
	Path    string     `json:"path"`
	Entries []DirEntry `json:"entries"`
}

func (e *Executor) ListDirectory(ctx context.Context, _ *mcp.CallToolRequest, in ListDirectoryInput) (*mcp.CallToolResult, ListDirectoryOutput, error) {
	if in.Path == "" {
		return denied("path is required"), ListDirectoryOutput{}, nil
	}

	resolved, err := resolveSafe(in.Path)
	if err != nil {
		return denied("path could not be resolved"), ListDirectoryOutput{}, nil
	}

	decision := e.Policy.Authorize(ctx, "fs.list", map[string]any{
		"path":      resolved,
		"recursive": in.Recursive,
	})
	if !decision.Allowed {
		return denied(decision.Reason), ListDirectoryOutput{}, nil
	}

	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return denied("path is not a readable directory"), ListDirectoryOutput{}, nil
	}

	var entries []DirEntry
	var walk func(dir string, recurse bool) error
	walk = func(dir string, recurse bool) error {
		items, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, item := range items {
			full := filepath.Join(dir, item.Name())
			if in.Glob != "" {
				matched, _ := doublestar.Match(in.Glob, item.Name())
				if !matched && !item.IsDir() {
					continue
				}
			}
			fi, err := item.Info()
			if err != nil {
				continue
			}
			entries = append(entries, DirEntry{
				Name:       item.Name(),
				Path:       full,
				IsDir:      item.IsDir(),
				SizeBytes:  fi.Size(),
				ModifiedAt: fi.ModTime().UTC().Format(time.RFC3339),
			})
			if recurse && item.IsDir() {
				if err := walk(full, true); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(resolved, in.Recursive); err != nil {
		return denied("directory could not be listed"), ListDirectoryOutput{}, nil
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	return nil, ListDirectoryOutput{Path: in.Path, Entries: entries}, nil
}

// resolveSafe resolves symlinks before any policy match happens, per
// design.md §5/Appendix A ("match after symlink resolution").
func resolveSafe(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Path may not exist yet from the caller's point of view; fall
		// back to the absolute, cleaned path so Stat below can produce a
		// clear "not found" rather than a resolution error.
		return filepath.Clean(abs), nil
	}
	return resolved, nil
}

func denied(reason string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "Denied: " + reason}},
	}
}
