package eventstore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/types"
)

// JSONLStore is the 0.1.0 EventStore implementation.
// It writes events as newline-delimited JSON to append-only files,
// bucketed by date for retention management.
type JSONLStore struct {
	writers  map[string]*bufio.Writer
	files    map[string]*os.File
	basePath string
	mu       sync.Mutex
}

// NewJSONLStore creates a new JSONL-backed event store.
func NewJSONLStore(basePath string) (*JSONLStore, error) {
	if err := os.MkdirAll(basePath, 0o750); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}

	return &JSONLStore{
		basePath: basePath,
		writers:  make(map[string]*bufio.Writer),
		files:    make(map[string]*os.File),
	}, nil
}

// Append writes an event to the appropriate date-bucketed JSONL file.
func (s *JSONLStore) Append(ctx context.Context, event *types.Event) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket := s.bucketKey(event.TenantID, event.Timestamp)
	w, err := s.getWriter(bucket)
	if err != nil {
		return "", fmt.Errorf("get writer for bucket %s: %w", bucket, err)
	}

	data, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("marshal event: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return "", fmt.Errorf("write event: %w", err)
	}
	if err := w.WriteByte('\n'); err != nil {
		return "", fmt.Errorf("write newline: %w", err)
	}
	if err := w.Flush(); err != nil {
		return "", fmt.Errorf("flush: %w", err)
	}

	return bucket + ":" + event.ID, nil
}

// Query retrieves events matching the filter by scanning JSONL files.
// This is acceptable for 0.1.0; in 1.0.0 this becomes a Kafka consumer + S3 query.
func (s *JSONLStore) Query(ctx context.Context, filter QueryFilter) ([]*types.Event, error) {
	s.mu.Lock()
	// Flush all writers before reading
	for _, w := range s.writers {
		w.Flush()
	}
	s.mu.Unlock()

	var results []*types.Event

	err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".jsonl" {
			return err
		}

		events, err := s.scanFile(ctx, path, filter)
		if err != nil {
			return fmt.Errorf("scan %s: %w", path, err)
		}
		results = append(results, events...)

		if filter.Limit > 0 && len(results) >= filter.Limit {
			results = results[:filter.Limit]
			return filepath.SkipAll
		}
		return nil
	})

	return results, err
}

// Stream returns a channel that tails the event store for new events.
func (s *JSONLStore) Stream(ctx context.Context, filter QueryFilter) (<-chan *types.Event, error) {
	ch := make(chan *types.Event, 128)
	go func() {
		defer close(ch)
		s.pollEvents(ctx, filter, ch)
	}()
	return ch, nil
}

// pollEvents is the polling loop for Stream. Separated to keep Stream's cognitive complexity low.
func (s *JSONLStore) pollEvents(ctx context.Context, filter QueryFilter, ch chan<- *types.Event) {
	// Simple polling implementation for 0.1.0.
	// In 1.0.0 this becomes a Kafka consumer.
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var lastSeen time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f := filter
			if !lastSeen.IsZero() {
				f.After = lastSeen
			}
			events, err := s.Query(ctx, f)
			if err != nil {
				continue
			}
			for _, e := range events {
				select {
				case ch <- e:
					lastSeen = e.Timestamp
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// Close flushes and closes all open files.
func (s *JSONLStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	for key, w := range s.writers {
		if err := w.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
		if f, ok := s.files[key]; ok {
			if err := f.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	s.writers = make(map[string]*bufio.Writer)
	s.files = make(map[string]*os.File)
	return firstErr
}

// bucketKey generates the storage key for a tenant + time window.
// Format: {tenant}/{date}.jsonl — one file per tenant per day.
func (s *JSONLStore) bucketKey(tenantID string, t time.Time) string {
	if tenantID == "" {
		tenantID = "_default"
	}
	return filepath.Join(tenantID, t.UTC().Format("2006-01-02"))
}

// getWriter returns a buffered writer for the given bucket, creating the file if needed.
func (s *JSONLStore) getWriter(bucket string) (*bufio.Writer, error) {
	if w, ok := s.writers[bucket]; ok {
		return w, nil
	}

	path := filepath.Join(s.basePath, bucket+".jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}

	w := bufio.NewWriterSize(f, 64*1024) // 64KB buffer
	s.writers[bucket] = w
	s.files[bucket] = f
	return w, nil
}

// scanFile reads a JSONL file and returns events matching the filter.
func (s *JSONLStore) scanFile(ctx context.Context, path string, filter QueryFilter) ([]*types.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []*types.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB max line

	for scanner.Scan() {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		var event types.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue // Skip malformed lines — log in production
		}

		if s.matchesFilter(&event, filter) {
			results = append(results, &event)
		}
	}

	return results, scanner.Err()
}

// matchesFilter checks whether an event satisfies the query criteria.
func (s *JSONLStore) matchesFilter(event *types.Event, f QueryFilter) bool {
	if f.SessionID != "" && event.SessionID != f.SessionID {
		return false
	}
	if f.AgentID != "" && event.AgentID != f.AgentID {
		return false
	}
	if f.TenantID != "" && event.TenantID != f.TenantID {
		return false
	}
	if !f.After.IsZero() && !event.Timestamp.After(f.After) {
		return false
	}
	if !f.Before.IsZero() && !event.Timestamp.Before(f.Before) {
		return false
	}
	if len(f.Types) > 0 {
		matched := false
		for _, t := range f.Types {
			if event.Type == t {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// Export writes events matching the filter to an io.Writer as JSONL.
func (s *JSONLStore) Export(ctx context.Context, filter QueryFilter, w io.Writer) (int64, error) {
	events, err := s.Query(ctx, filter)
	if err != nil {
		return 0, err
	}

	var count int64
	encoder := json.NewEncoder(w)
	for _, e := range events {
		if err := encoder.Encode(e); err != nil {
			return count, fmt.Errorf("encode event %s: %w", e.ID, err)
		}
		count++
	}
	return count, nil
}
