package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// HashChainSink is the 0.1.0 AuditSink implementation.
// It writes structured JSON entries to an append-only file with
// SHA-256 hash chaining for tamper detection.
type HashChainSink struct {
	mu           sync.Mutex
	file         *os.File
	writer       *bufio.Writer
	seq          int64
	previousHash string
	path         string
}

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// NewHashChainSink creates a new hash-chained audit log.
// If the file exists, it resumes from the last entry to maintain the chain.
func NewHashChainSink(path string) (*HashChainSink, error) {
	s := &HashChainSink{
		path:         path,
		previousHash: genesisHash,
	}

	// Resume chain state from existing log
	if err := s.resumeChain(); err != nil {
		return nil, fmt.Errorf("resume audit chain: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	s.file = f
	s.writer = bufio.NewWriter(f)
	return s, nil
}

// Log writes a hash-chained audit entry.
func (s *HashChainSink) Log(ctx context.Context, entry Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Assign chain fields
	s.seq++
	entry.SequenceNum = s.seq
	entry.PreviousHash = s.previousHash
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// Compute entry hash: SHA-256(seq || previous_hash || canonical_json_of_content)
	entry.EntryHash = s.computeHash(entry)
	s.previousHash = entry.EntryHash

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	if err := s.writer.WriteByte('\n'); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}

	// Audit entries are flushed and synced immediately — no buffering risk.
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("fsync: %w", err)
	}

	return nil
}

// Verify checks the integrity of the hash chain.
// Returns -1 if the chain is intact, or the sequence number of the first broken link.
func (s *HashChainSink) Verify(ctx context.Context, fromSeq int64) (int64, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return -1, fmt.Errorf("open audit log for verification: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	expectedPrev := genesisHash
	var lastSeq int64

	for scanner.Scan() {
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}

		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return lastSeq + 1, fmt.Errorf("corrupt entry after seq %d: %w", lastSeq, err)
		}

		if entry.SequenceNum < fromSeq {
			expectedPrev = entry.EntryHash
			lastSeq = entry.SequenceNum
			continue
		}

		// Verify chain link
		if entry.PreviousHash != expectedPrev {
			return entry.SequenceNum, nil
		}

		// Verify entry integrity
		computed := s.computeHash(entry)
		if entry.EntryHash != computed {
			return entry.SequenceNum, nil
		}

		expectedPrev = entry.EntryHash
		lastSeq = entry.SequenceNum
	}

	if err := scanner.Err(); err != nil {
		return -1, fmt.Errorf("scan error: %w", err)
	}

	return -1, nil // Chain intact
}

// LatestCheckpoint returns the current chain head.
func (s *HashChainSink) LatestCheckpoint() (string, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.previousHash, s.seq
}

// Close flushes and closes the audit log file.
func (s *HashChainSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writer.Flush(); err != nil {
		return err
	}
	return s.file.Close()
}

// computeHash produces the SHA-256 hash for an audit entry.
// The hash covers: seq, previous_hash, timestamp, action, outcome, actor, resource, detail.
// The entry_hash field itself is excluded.
func (s *HashChainSink) computeHash(entry Entry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|%s|%s|%s|%s",
		entry.SequenceNum,
		entry.PreviousHash,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.Action,
		entry.Outcome,
		entry.ActorID,
		entry.Resource,
		entry.Detail,
	)
	return hex.EncodeToString(h.Sum(nil))
}

// resumeChain reads the existing audit log to recover the latest
// sequence number and hash, allowing the chain to continue after restart.
func (s *HashChainSink) resumeChain() error {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil // Fresh start
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	var lastEntry Entry
	found := false

	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		lastEntry = entry
		found = true
	}

	if found {
		s.seq = lastEntry.SequenceNum
		s.previousHash = lastEntry.EntryHash
	}

	return scanner.Err()
}
