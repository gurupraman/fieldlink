package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ExportCEF reads the audit log at path and writes it to w in Common Event
// Format, for `fieldlink audit export --format cef` (design.md §8).
func ExportCEF(path string, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("audit export: %w", err)
		}
		if _, err := io.WriteString(w, recordToCEF(rec)+"\n"); err != nil {
			return err
		}
	}
	return sc.Err()
}

func recordToCEF(rec Record) string {
	severity := "3"
	if rec.Decision == "deny" {
		severity = "6"
	}
	ext := fmt.Sprintf(
		"rt=%s suser=%s cs1Label=grantId cs1=%s cs2Label=sessionId cs2=%s "+
			"cs3Label=paramsDigest cs3=%s cs4Label=callerId cs4=%s outcome=%s reason=%s cnt=%d",
		rec.TS, cefEscape(rec.AgentID), cefEscape(rec.GrantID), cefEscape(rec.SessionID),
		cefEscape(rec.ParamsDigest), cefEscape(rec.CallerID), cefEscape(rec.Decision), cefEscape(rec.Reason), rec.Seq,
	)
	return fmt.Sprintf(
		"CEF:0|FieldLink|fieldlink|0.1.0-dev|%s|%s %s|%s|%s",
		cefEscapeHeader(rec.Capability), cefEscapeHeader(rec.Capability), cefEscapeHeader(rec.Decision), severity, ext,
	)
}

// cefEscape escapes CEF extension field values (pipe and equals are
// structural in the header, backslash/equals/newline are structural in
// extension key=value pairs).
func cefEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`)
	return r.Replace(s)
}

// cefEscapeHeader escapes CEF header field values (pipe and backslash are
// structural there).
func cefEscapeHeader(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `|`, `\|`)
	return r.Replace(s)
}
