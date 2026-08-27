package fs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	smb2 "github.com/hirochachacha/go-smb2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// An smb:// path is smb://<share-name>/<rel-path>, where <share-name> is a
// key into config.yaml's smb_shares: map — not the literal SMB share name
// on the wire. This keeps the tool call symbolic (design.md's whole
// rationale for register maps applies here too: the model shouldn't need
// to know a real host/share/credential set, just a name FieldLink already
// trusts) and matches how db.query takes a named datasource rather than a
// connection string.
type smbConn struct {
	tcpConn net.Conn
	session *smb2.Session
	share   *smb2.Share
}

func parseSMBPath(p string) (shareName, rel string, ok bool) {
	rest := strings.TrimPrefix(p, "smb://")
	if rest == p {
		return "", "", false
	}
	parts := strings.SplitN(rest, "/", 2)
	shareName = parts[0]
	if shareName == "" {
		return "", "", false
	}
	if len(parts) == 2 {
		rel = parts[1]
	}
	// Reject traversal attempts explicitly: path.Clean alone would
	// silently collapse "a/../../b" without signaling that the input
	// tried to escape the share root, which is exactly the case worth
	// refusing outright rather than clamping.
	cleaned := path.Clean("/" + rel)[1:]
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", "", false
	}
	return shareName, cleaned, true
}

func (e *Executor) smbShareFor(ctx context.Context, name string) (*smb2.Share, error) {
	e.smbMu.Lock()
	defer e.smbMu.Unlock()

	if e.smbConns == nil {
		e.smbConns = make(map[string]*smbConn)
	}
	if c, ok := e.smbConns[name]; ok {
		return c.share, nil
	}

	cfg, ok := e.SMBShares[name]
	if !ok {
		return nil, fmt.Errorf("smb share %q is not configured", name)
	}

	port := cfg.Port
	if port <= 0 {
		port = 445
	}
	tcpConn, err := net.Dial("tcp", net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}

	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     os.Getenv(cfg.UsernameEnv),
			Password: os.Getenv(cfg.PasswordEnv),
			Domain:   cfg.Domain,
		},
	}
	session, err := dialer.DialContext(ctx, tcpConn)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}
	share, err := session.Mount(cfg.Share)
	if err != nil {
		session.Logoff()
		tcpConn.Close()
		return nil, err
	}

	e.smbConns[name] = &smbConn{tcpConn: tcpConn, session: session, share: share}
	return share, nil
}

func (e *Executor) smbReadFile(ctx context.Context, rawPath string, maxBytes int64) (*mcp.CallToolResult, ReadFileOutput, error) {
	shareName, rel, ok := parseSMBPath(rawPath)
	if !ok {
		return denied("path is not a valid smb:// URI"), ReadFileOutput{}, nil
	}

	decision := e.Policy.Authorize(ctx, "fs.read", map[string]any{
		"path":      rawPath,
		"max_bytes": maxBytes,
	})
	if !decision.Allowed {
		return denied(decision.Reason), ReadFileOutput{}, nil
	}

	share, err := e.smbShareFor(ctx, shareName)
	if err != nil {
		return denied("smb share is not reachable"), ReadFileOutput{}, nil
	}

	info, err := share.Stat(rel)
	if err != nil {
		return denied("file not found or not readable"), ReadFileOutput{}, nil
	}
	if info.IsDir() {
		return denied("path is a directory, not a file"), ReadFileOutput{}, nil
	}

	f, err := share.Open(rel)
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
			Path:       rawPath,
			SizeBytes:  info.Size(),
			Truncated:  true,
			Digest:     fmt.Sprintf("sha256:%x", h.Sum(nil)),
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
				"%s is %d bytes, exceeding max_bytes=%d; returning digest only", rawPath, info.Size(), maxBytes)}},
		}, out, nil
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return denied("file could not be read"), ReadFileOutput{}, nil
	}

	return nil, ReadFileOutput{
		Path:       rawPath,
		Content:    string(data),
		SizeBytes:  info.Size(),
		ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
	}, nil
}

func (e *Executor) smbListDirectory(ctx context.Context, rawPath, glob string, recursive bool) (*mcp.CallToolResult, ListDirectoryOutput, error) {
	shareName, rel, ok := parseSMBPath(rawPath)
	if !ok {
		return denied("path is not a valid smb:// URI"), ListDirectoryOutput{}, nil
	}

	decision := e.Policy.Authorize(ctx, "fs.list", map[string]any{
		"path":      rawPath,
		"recursive": recursive,
	})
	if !decision.Allowed {
		return denied(decision.Reason), ListDirectoryOutput{}, nil
	}

	share, err := e.smbShareFor(ctx, shareName)
	if err != nil {
		return denied("smb share is not reachable"), ListDirectoryOutput{}, nil
	}

	var entries []DirEntry
	var walk func(dir string, recurse bool) error
	walk = func(dir string, recurse bool) error {
		items, err := share.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, item := range items {
			full := path.Join(dir, item.Name())
			if glob != "" {
				matched, _ := doublestar.Match(glob, item.Name())
				if !matched && !item.IsDir() {
					continue
				}
			}
			entries = append(entries, DirEntry{
				Name:       item.Name(),
				Path:       "smb://" + shareName + "/" + full,
				IsDir:      item.IsDir(),
				SizeBytes:  item.Size(),
				ModifiedAt: item.ModTime().UTC().Format(time.RFC3339),
			})
			if recurse && item.IsDir() {
				if err := walk(full, true); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(rel, recursive); err != nil {
		return denied("directory could not be listed"), ListDirectoryOutput{}, nil
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	return nil, ListDirectoryOutput{Path: rawPath, Entries: entries}, nil
}
