// Package audit defines the interface for tamper-evident audit logging.
// The 0.1.0 implementation uses SHA-256 hash chaining to a local file.
// The 1.0.0 implementation will add Merkle trees and Rekor transparency log submission.
package audit

import (
	"context"
	"time"
)

// ActionType classifies the auditable operation.
type ActionType string

const (
	ActionAuthenticate ActionType = "authenticate"
	ActionIngestEvent  ActionType = "ingest_event"
	ActionQueryEvents  ActionType = "query_events"
	ActionAnalyze      ActionType = "analyze"
	ActionConfigChange ActionType = "config_change"
	ActionDeleteData   ActionType = "delete_data"
	ActionExportData   ActionType = "export_data"
	ActionKeyRotation  ActionType = "key_rotation"
	ActionCertIssue    ActionType = "cert_issue"
	ActionAccessDenied ActionType = "access_denied"
)

// Outcome indicates whether the audited action succeeded.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// Entry is a single audit record.
type Entry struct {
	Timestamp     time.Time         `json:"timestamp"`
	Action        ActionType        `json:"action"`
	Outcome       Outcome           `json:"outcome"`
	ActorID       string            `json:"actor_id"` // Cert SAN, API key fingerprint, or system identity
	Resource      string            `json:"resource"` // What was acted upon
	Detail        string            `json:"detail,omitempty"`
	SourceIP      string            `json:"source_ip,omitempty"`
	CorrelationID string            `json:"correlation_id"` // Ties to request chain
	Labels        map[string]string `json:"labels,omitempty"`

	// Integrity — set by the Sink implementation
	PreviousHash string `json:"previous_hash"` // Hash chain link
	EntryHash    string `json:"entry_hash"`    // Hash of this entry
	SequenceNum  int64  `json:"seq"`           // Monotonic counter
}

// Sink is the core audit logging interface.
// Implementations must be safe for concurrent use and must guarantee
// that entries are written in sequence order with no gaps.
type Sink interface {
	// Log writes an audit entry. The implementation is responsible for
	// computing sequence numbers and hash chain links.
	Log(ctx context.Context, entry Entry) error

	// Verify checks the integrity of the audit chain from the given
	// sequence number to the latest entry. Returns the first broken
	// link, or -1 if the chain is intact.
	Verify(ctx context.Context, fromSeq int64) (brokenAt int64, err error)

	// LatestCheckpoint returns the most recent root hash and sequence number.
	LatestCheckpoint() (hash string, seq int64)

	// Close flushes and releases resources.
	Close() error
}

// Querier supports searching the audit log. Optional interface — not all
// backends may support querying (e.g., a pure append-only log).
type Querier interface {
	// Search returns audit entries matching the filter.
	Search(ctx context.Context, filter AuditFilter) ([]Entry, error)
}

// AuditFilter defines search criteria for audit entries.
type AuditFilter struct {
	ActorID  string
	Actions  []ActionType
	Outcomes []Outcome
	After    time.Time
	Before   time.Time
	Resource string
	Limit    int
}
