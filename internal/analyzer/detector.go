package analyzer

import (
	"time"

	"github.com/agent-transponder/agent-transponder/internal/types"
)

// Detector analyzes events and produces findings.
// Implementations are stateful: each call to Analyze accumulates session
// context and emits findings when thresholds are crossed.
type Detector interface {
	// Name returns the detector's identifier.
	Name() string

	// Analyze processes a single event and returns any new findings.
	// May return zero findings if the event is not anomalous or does not yet
	// push the session past a detection threshold.
	Analyze(event *types.Event) ([]Finding, error)

	// Reset clears all internal state (for testing or session boundaries).
	Reset()
}

// Finding is a single anomaly detected by a Detector.
// Written as JSONL to the findings directory.
type Finding struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	AgentID    string    `json:"agent_id"`
	TenantID   string    `json:"tenant_id"`
	Timestamp  time.Time `json:"timestamp"`
	Detector   string    `json:"detector"`
	Type       string    `json:"type"`       // types.DetectionType value
	Severity   string    `json:"severity"`   // types.Severity value
	Confidence float64   `json:"confidence"` // 0.0–1.0
	Message    string    `json:"message"`
	EventIDs   []string  `json:"event_ids"`
	Evidence   string    `json:"evidence,omitempty"`
}
