// Package eventstore defines the interface for persisting telemetry events.
// The 0.1.0 implementation writes append-only JSONL files.
// The 1.0.0 implementation will publish to Kafka + persist to S3.
package eventstore

import (
	"context"
	"io"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/types"
)

// Store is the core persistence interface for telemetry events.
// Implementations must be safe for concurrent use.
type Store interface {
	// Append writes an event to the store. The event must already be
	// validated, redacted, and HMAC-verified before reaching the store.
	// Returns the storage key (e.g., file path or Kafka offset).
	Append(ctx context.Context, event *types.Event) (string, error)

	// Query retrieves events matching the given filter.
	// Results are returned in chronological order.
	Query(ctx context.Context, filter QueryFilter) ([]*types.Event, error)

	// Stream returns a channel of events for real-time consumers.
	// The channel is closed when the context is cancelled.
	Stream(ctx context.Context, filter QueryFilter) (<-chan *types.Event, error)

	// Close flushes pending writes and releases resources.
	Close() error
}

// QueryFilter defines criteria for retrieving events.
type QueryFilter struct {
	After     time.Time
	Before    time.Time
	SessionID string
	AgentID   string
	TenantID  string
	Types     []types.EventType
	Limit     int
}

// RetentionManager handles TTL enforcement and secure deletion.
// Separated from Store because deletion is a privileged, audited operation.
type RetentionManager interface {
	// EnforceTTL scans for expired data and triggers secure deletion.
	// Returns the number of buckets deleted.
	EnforceTTL(ctx context.Context) (int, error)

	// DeleteBucket securely deletes a time/tenant bucket via crypto-shredding.
	// This destroys the data encryption key, rendering the data unrecoverable.
	DeleteBucket(ctx context.Context, bucketID string) error
}

// Metrics exposes store health for the Prometheus exporter.
type Metrics interface {
	// EventCount returns total events stored, by tenant.
	EventCount(ctx context.Context) (map[string]int64, error)

	// StorageBytes returns bytes used, by tenant.
	StorageBytes(ctx context.Context) (map[string]int64, error)

	// OldestEvent returns the timestamp of the oldest retained event.
	OldestEvent(ctx context.Context) (time.Time, error)
}

// Exporter supports bulk export for replay or migration.
type Exporter interface {
	// Export writes events matching the filter to the given writer as JSONL.
	Export(ctx context.Context, filter QueryFilter, w io.Writer) (int64, error)
}
