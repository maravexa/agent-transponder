// Package types defines the canonical event schema for Agent Transponder.
// Every component — SDK, ingestion, analysis, exporter — speaks this schema.
// Changes here must be backward-compatible; add fields, never remove them.
package types

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// EventType classifies the kind of telemetry captured.
type EventType string

const (
	EventPrompt        EventType = "prompt"
	EventResponse      EventType = "response"
	EventToolCall      EventType = "tool_call"
	EventToolResult    EventType = "tool_result"
	EventMemoryRead    EventType = "memory_read"
	EventMemoryWrite   EventType = "memory_write"
	EventReasoningStep EventType = "reasoning_step"
	EventError         EventType = "error"
	EventRetry         EventType = "retry"
	EventMetadata      EventType = "metadata"
)

// Severity indicates the urgency level of an event.
type Severity string

const (
	SeverityDebug    Severity = "debug"
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// Event is the core telemetry unit flowing through Agent Transponder.
// It is designed to be serialized as JSON and stored in append-only logs.
type Event struct {
	// Identity
	ID        string `json:"id"`         // UUIDv7 — time-ordered, globally unique
	SessionID string `json:"session_id"` // Groups events from a single agent run
	AgentID   string `json:"agent_id"`   // Identifies the agent instance (from cert SAN)
	TenantID  string `json:"tenant_id"`  // Multi-tenant isolation key

	// Classification
	Type     EventType `json:"type"`
	Severity Severity  `json:"severity"`

	// Timing
	Timestamp  time.Time `json:"timestamp"`             // When the event occurred at the agent
	ReceivedAt time.Time `json:"received_at,omitempty"` // When ingestion received it

	// Content — only one of these is populated per event type
	Prompt    *PromptData    `json:"prompt,omitempty"`
	Response  *ResponseData  `json:"response,omitempty"`
	ToolCall  *ToolCallData  `json:"tool_call,omitempty"`
	Memory    *MemoryData    `json:"memory,omitempty"`
	Reasoning *ReasoningData `json:"reasoning,omitempty"`
	Error     *ErrorData     `json:"error,omitempty"`

	// Model metadata
	Model      string            `json:"model,omitempty"`
	TokenUsage *TokenUsage       `json:"token_usage,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"` // User-defined key-value pairs

	// Causal attribution — populated by framework integrations
	RunID       string   `json:"run_id,omitempty"`
	ParentRunID string   `json:"parent_run_id,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	// Integrity — set by the SDK, verified by ingestion
	HMAC string `json:"hmac"` // HMAC-SHA256 over canonical JSON (excluding this field)

	// Redaction tracking — set by ingestion after redaction
	RedactedFields []string `json:"redacted_fields,omitempty"`

	// Duration is set for timed events (tool calls, response generation, etc.)
	Duration time.Duration `json:"duration,omitempty"`
}

// PromptData captures the input sent to a model.
type PromptData struct {
	Content    string `json:"content"`
	Role       string `json:"role,omitempty"` // "user", "system", etc.
	TokenCount int    `json:"token_count,omitempty"`
}

// ResponseData captures the model's output.
type ResponseData struct {
	Content      string `json:"content"`
	FinishReason string `json:"finish_reason,omitempty"` // "stop", "length", "tool_use"
	TokenCount   int    `json:"token_count,omitempty"`
}

// ToolCallData captures a tool invocation and its result.
type ToolCallData struct {
	ToolName   string          `json:"tool_name"`
	ErrorMsg   string          `json:"error_msg,omitempty"`
	Arguments  json.RawMessage `json:"arguments,omitempty"` // Preserved as raw JSON
	Result     json.RawMessage `json:"result,omitempty"`    // Preserved as raw JSON
	RetryCount int             `json:"retry_count,omitempty"`
	Success    bool            `json:"success"`
}

// MemoryData captures agent memory operations.
type MemoryData struct {
	Operation string `json:"operation"` // "read" or "write"
	Key       string `json:"key"`
	Value     string `json:"value,omitempty"`
}

// ReasoningData captures chain-of-thought or reasoning traces.
type ReasoningData struct {
	Content string `json:"content"`
	Step    int    `json:"step"`
}

// ErrorData captures error details.
type ErrorData struct {
	Code       string `json:"code,omitempty"`
	Message    string `json:"message"`
	Stacktrace string `json:"stacktrace,omitempty"`
	Retryable  bool   `json:"retryable"`
}

// TokenUsage tracks token consumption.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// AnalysisResult is produced by the analysis engine for a batch of events.
type AnalysisResult struct {
	ID         string          `json:"id"`
	SessionID  string          `json:"session_id"`
	AgentID    string          `json:"agent_id"`
	TenantID   string          `json:"tenant_id"`
	Timestamp  time.Time       `json:"timestamp"`
	Detections []Detection     `json:"detections"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// DetectionType classifies what the analysis engine found.
type DetectionType string

const (
	DetectionLoop             DetectionType = "task_loop"
	DetectionToolMisuse       DetectionType = "tool_misuse"
	DetectionGoalDrift        DetectionType = "goal_drift"
	DetectionHallucination    DetectionType = "hallucination"
	DetectionFailureCascade   DetectionType = "failure_cascade"
	DetectionRewardHacking    DetectionType = "reward_hacking"
	DetectionPersonalityDrift DetectionType = "personality_drift"
)

// Detection represents a single finding from the analysis engine.
type Detection struct {
	Type       DetectionType `json:"type"`
	Severity   Severity      `json:"severity"`
	Message    string        `json:"message"`
	Evidence   string        `json:"evidence,omitempty"`
	EventIDs   []string      `json:"event_ids"`  // Events that triggered this detection
	Confidence float64       `json:"confidence"` // 0.0–1.0
}

// ComputeHMAC calculates the HMAC-SHA256 for this event.
// The HMAC field itself is excluded from the computation.
//
// Keys are sorted alphabetically in the canonical JSON to ensure
// cross-language compatibility — the Python SDK uses json.dumps(sort_keys=True).
// Go's json.Marshal on map[string]interface{} sorts keys alphabetically,
// matching Python's sort_keys=True.
func (e *Event) ComputeHMAC(key []byte) (string, error) {
	// Temporarily clear HMAC to compute over the rest
	savedHMAC := e.HMAC
	e.HMAC = ""
	defer func() { e.HMAC = savedHMAC }()

	// Round-trip through map[string]interface{} to produce sorted keys.
	// This is required for cross-language HMAC compatibility — the Python
	// SDK uses json.dumps(sort_keys=True) as its canonical form.
	raw, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("marshal for hmac: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("unmarshal for hmac sort: %w", err)
	}
	delete(m, "hmac") // Exclude hmac field from signature computation
	canonical, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("remarshal sorted for hmac: %w", err)
	}

	slog.Debug("HMAC canonical JSON", "json", string(canonical), "event_id", e.ID)

	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHMAC checks whether the event's HMAC is valid for the given key.
func (e *Event) VerifyHMAC(key []byte) (bool, error) {
	expected, err := e.ComputeHMAC(key)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(e.HMAC), []byte(expected)), nil
}
