package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// VerifyResult is the outcome of walking an audit log's hash chain.
type VerifyResult struct {
	OK           bool
	RecordCount  int64
	BrokenAtSeq  int64 // valid only when !OK
	BrokenAtLine int   // 1-indexed
	BrokenReason string
}

// Verify walks path's hash chain and reports the first break, per
// `fieldlink audit verify` (design.md §8). A missing file is treated as an
// empty, valid chain — there's nothing to break yet.
func Verify(path string) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &VerifyResult{OK: true}, nil
		}
		return nil, err
	}
	defer f.Close()

	res := &VerifyResult{OK: true}
	prevHash := ""
	var expectedSeq int64

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			res.OK = false
			res.BrokenAtLine = line
			res.BrokenReason = fmt.Sprintf("line %d is not valid JSON: %v", line, err)
			return res, nil
		}

		expectedSeq++
		if rec.Seq != expectedSeq {
			res.OK = false
			res.BrokenAtLine = line
			res.BrokenAtSeq = rec.Seq
			res.BrokenReason = fmt.Sprintf("expected seq %d, got %d", expectedSeq, rec.Seq)
			return res, nil
		}
		if rec.PrevHash != prevHash {
			res.OK = false
			res.BrokenAtLine = line
			res.BrokenAtSeq = rec.Seq
			res.BrokenReason = "prev_hash does not match the previous record's hash"
			return res, nil
		}

		claimedHash := rec.Hash
		computed, err := hashRecord(rec)
		if err != nil {
			return nil, err
		}
		if computed != claimedHash {
			res.OK = false
			res.BrokenAtLine = line
			res.BrokenAtSeq = rec.Seq
			res.BrokenReason = "hash does not match the record's contents"
			return res, nil
		}

		prevHash = claimedHash
		res.RecordCount = expectedSeq
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

// lastRecord returns the last valid record in path, or nil if the file
// doesn't exist or is empty. Used by Open to resume a chain across
// restarts without re-validating the whole file on every startup.
func lastRecord(path string) (*Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var last *Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue // Verify surfaces corruption; Open just resumes best-effort
		}
		r := rec
		last = &r
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return last, nil
}
