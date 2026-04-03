package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/identity"
	"github.com/agent-transponder/agent-transponder/internal/policy"
	"github.com/agent-transponder/agent-transponder/internal/redaction"
	"github.com/agent-transponder/agent-transponder/internal/types"
)

// stubPolicy controls policy decisions for tests.
type stubPolicy struct {
	decision policy.Decision
	reason   string
}

func (p *stubPolicy) Evaluate(_ context.Context, _ policy.EvalRequest) (*policy.EvalResult, error) { //nolint:unparam
	d := p.decision
	if d == "" {
		d = policy.DecisionAllow
	}
	return &policy.EvalResult{Decision: d, Reason: p.reason}, nil
}
func (p *stubPolicy) Reload(_ context.Context) error { return nil }
func (p *stubPolicy) Close() error                   { return nil }

func makeEvent(eventType types.EventType) *types.Event {
	return &types.Event{
		ID:        "test-id-001",
		SessionID: "sess-001",
		AgentID:   "test-agent",
		TenantID:  "test-tenant",
		Type:      eventType,
		Severity:  types.SeverityInfo,
		Timestamp: time.Now().UTC(),
	}
}

func newForwarder() *AnalysisForwarder {
	return &AnalysisForwarder{
		cfg: AnalysisConfig{
			BatchSize:               10,
			FlushInterval:           time.Minute,
			CircuitBreakerThreshold: 5,
			CircuitBreakerCooldown:  time.Minute,
		},
		logger:  slog.Default(),
		eventCh: make(chan *types.Event, 100),
	}
}

// ── schema validation tests ───────────────────────────────────────────────────

func TestValidateEvent_ValidPrompt(t *testing.T) {
	e := makeEvent(types.EventPrompt)
	if err := validateEvent(e); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateEvent_AllKnownTypes(t *testing.T) {
	types_ := []types.EventType{
		types.EventPrompt, types.EventResponse, types.EventToolCall,
		types.EventToolResult, types.EventMemoryRead, types.EventMemoryWrite,
		types.EventReasoningStep, types.EventError, types.EventRetry, types.EventMetadata,
	}
	for _, et := range types_ {
		e := makeEvent(et)
		if err := validateEvent(e); err != nil {
			t.Errorf("type %q: unexpected error: %v", et, err)
		}
	}
}

func TestValidateEvent_MissingID(t *testing.T) {
	e := makeEvent(types.EventPrompt)
	e.ID = ""
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestValidateEvent_MissingSessionID(t *testing.T) {
	e := makeEvent(types.EventPrompt)
	e.SessionID = ""
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for missing SessionID")
	}
}

func TestValidateEvent_UnknownType(t *testing.T) {
	e := makeEvent("unknown_type")
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for unknown event type")
	}
}

func TestValidateEvent_MissingTimestamp(t *testing.T) {
	e := makeEvent(types.EventPrompt)
	e.Timestamp = time.Time{}
	if err := validateEvent(e); err == nil {
		t.Fatal("expected error for zero timestamp")
	}
}

// ── HMAC tests ────────────────────────────────────────────────────────────────

func TestHMACVerification_Valid(t *testing.T) {
	key := []byte("test-secret-key-for-hmac-verification")
	e := makeEvent(types.EventPrompt)
	e.Prompt = &types.PromptData{Content: "hello world", Role: "user"}

	mac, err := e.ComputeHMAC(key)
	if err != nil {
		t.Fatalf("ComputeHMAC: %v", err)
	}
	e.HMAC = mac

	ok, err := e.VerifyHMAC(key)
	if err != nil {
		t.Fatalf("VerifyHMAC: %v", err)
	}
	if !ok {
		t.Fatal("expected HMAC to be valid")
	}
}

func TestHMACVerification_WrongKey(t *testing.T) {
	key := []byte("correct-key")
	wrongKey := []byte("wrong-key")

	e := makeEvent(types.EventPrompt)
	mac, err := e.ComputeHMAC(key)
	if err != nil {
		t.Fatalf("ComputeHMAC: %v", err)
	}
	e.HMAC = mac

	ok, err := e.VerifyHMAC(wrongKey)
	if err != nil {
		t.Fatalf("VerifyHMAC: %v", err)
	}
	if ok {
		t.Fatal("expected HMAC to be invalid with wrong key")
	}
}

func TestHMACVerification_TamperedContent(t *testing.T) {
	key := []byte("test-key")
	e := makeEvent(types.EventPrompt)
	e.Prompt = &types.PromptData{Content: "original content"}

	mac, err := e.ComputeHMAC(key)
	if err != nil {
		t.Fatalf("ComputeHMAC: %v", err)
	}
	e.HMAC = mac

	// Tamper with content after signing.
	e.Prompt.Content = "tampered content"

	ok, err := e.VerifyHMAC(key)
	if err != nil {
		t.Fatalf("VerifyHMAC: %v", err)
	}
	if ok {
		t.Fatal("expected HMAC to be invalid for tampered event")
	}
}

func TestHMACVerification_DifferentEventTypes(t *testing.T) {
	key := []byte("shared-key")

	// HMAC should differ between events with different content.
	e1 := makeEvent(types.EventPrompt)
	e1.Prompt = &types.PromptData{Content: "hello"}

	e2 := makeEvent(types.EventPrompt)
	e2.Prompt = &types.PromptData{Content: "world"}

	mac1, _ := e1.ComputeHMAC(key)
	mac2, _ := e2.ComputeHMAC(key)

	if mac1 == mac2 {
		t.Fatal("expected different HMACs for different event content")
	}
}

// ── redaction tests ───────────────────────────────────────────────────────────

func TestRedaction_ScrubsAWSKey(t *testing.T) {
	r, err := redaction.NewRegexRedactor(nil)
	if err != nil {
		t.Fatalf("NewRegexRedactor: %v", err)
	}

	e := makeEvent(types.EventPrompt)
	e.Prompt = &types.PromptData{
		Content: "My AWS key is AKIAIOSFODNN7EXAMPLE",
	}
	original := e.Prompt.Content

	redacted := r.Redact(e)
	if len(redacted) == 0 {
		t.Fatal("expected redaction to scrub at least one field")
	}
	if e.Prompt.Content == original {
		t.Fatal("expected prompt content to be redacted")
	}
}

func TestRedaction_ScrubsPassword(t *testing.T) {
	r, err := redaction.NewRegexRedactor(nil)
	if err != nil {
		t.Fatalf("NewRegexRedactor: %v", err)
	}

	e := makeEvent(types.EventError)
	e.Error = &types.ErrorData{
		Message: "connection failed: password=supersecret123",
	}

	r.Redact(e)

	if e.Error.Message == "connection failed: password=supersecret123" {
		t.Fatal("expected error message to be redacted")
	}
}

func TestRedaction_CleanContentUnchanged(t *testing.T) {
	r, err := redaction.NewRegexRedactor(nil)
	if err != nil {
		t.Fatalf("NewRegexRedactor: %v", err)
	}

	e := makeEvent(types.EventPrompt)
	e.Prompt = &types.PromptData{Content: "What is the capital of France?"}

	// Just ensure Redact doesn't panic on clean content.
	_ = r.Redact(e)
}

func TestRedaction_ToolCallArgs(t *testing.T) {
	r, err := redaction.NewRegexRedactor(nil)
	if err != nil {
		t.Fatalf("NewRegexRedactor: %v", err)
	}

	e := makeEvent(types.EventToolCall)
	e.ToolCall = &types.ToolCallData{
		ToolName: "db_query",
		ErrorMsg: "auth failed: password=mysecret",
	}

	redacted := r.Redact(e)
	if len(redacted) == 0 {
		t.Fatal("expected tool call error to be redacted")
	}
}

// ── policy evaluation tests ───────────────────────────────────────────────────

func TestPolicy_Allow(t *testing.T) {
	pol := &stubPolicy{decision: policy.DecisionAllow}
	agentIdent := &identity.AgentIdentity{AgentID: "test-agent", TenantID: "test-tenant"}

	result, err := pol.Evaluate(context.Background(), policy.EvalRequest{
		Agent: agentIdent, Action: "ingest", Resource: "events",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Decision != policy.DecisionAllow {
		t.Fatalf("expected Allow, got %s", result.Decision)
	}
}

func TestPolicy_Deny(t *testing.T) {
	pol := &stubPolicy{decision: policy.DecisionDeny, reason: "blocked agent"}
	agentIdent := &identity.AgentIdentity{AgentID: "bad-agent"}

	result, err := pol.Evaluate(context.Background(), policy.EvalRequest{
		Agent: agentIdent, Action: "ingest", Resource: "events",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Decision != policy.DecisionDeny {
		t.Fatalf("expected Deny, got %s", result.Decision)
	}
	if result.Reason != "blocked agent" {
		t.Errorf("expected reason %q, got %q", "blocked agent", result.Reason)
	}
}

func TestPolicy_Throttle(t *testing.T) {
	pol := &stubPolicy{decision: policy.DecisionThrottle}
	agentIdent := &identity.AgentIdentity{AgentID: "fast-agent"}

	result, err := pol.Evaluate(context.Background(), policy.EvalRequest{
		Agent: agentIdent, Action: "ingest", Resource: "events",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Decision != policy.DecisionThrottle {
		t.Fatalf("expected Throttle, got %s", result.Decision)
	}
}

// ── proto conversion tests ────────────────────────────────────────────────────

func TestEventToProtoRoundtrip_Prompt(t *testing.T) {
	original := &types.Event{
		ID:        "roundtrip-id",
		SessionID: "sess-rt",
		AgentID:   "agent-rt",
		TenantID:  "tenant-rt",
		Type:      types.EventPrompt,
		Severity:  types.SeverityInfo,
		Timestamp: time.Now().UTC().Truncate(time.Millisecond),
		Prompt: &types.PromptData{
			Content:    "test prompt",
			Role:       "user",
			TokenCount: 5,
		},
		Model: "gpt-4",
	}

	proto := eventToProto(original)
	got := protoToEvent(proto)

	if got.ID != original.ID {
		t.Errorf("ID: got %q, want %q", got.ID, original.ID)
	}
	if got.Type != original.Type {
		t.Errorf("Type: got %q, want %q", got.Type, original.Type)
	}
	if got.Severity != original.Severity {
		t.Errorf("Severity: got %q, want %q", got.Severity, original.Severity)
	}
	if got.Prompt == nil {
		t.Fatal("expected Prompt to be non-nil after roundtrip")
	}
	if got.Prompt.Content != original.Prompt.Content {
		t.Errorf("Prompt.Content: got %q, want %q", got.Prompt.Content, original.Prompt.Content)
	}
	if got.Prompt.Role != original.Prompt.Role {
		t.Errorf("Prompt.Role: got %q, want %q", got.Prompt.Role, original.Prompt.Role)
	}
}

func TestEventToProtoRoundtrip_ToolCall(t *testing.T) {
	original := &types.Event{
		ID:        "tc-roundtrip",
		SessionID: "sess-tc",
		AgentID:   "agent-tc",
		TenantID:  "tenant-tc",
		Type:      types.EventToolCall,
		Severity:  types.SeverityInfo,
		Timestamp: time.Now().UTC(),
		ToolCall: &types.ToolCallData{
			ToolName:   "weather_api",
			Success:    false,
			ErrorMsg:   "timeout",
			RetryCount: 2,
		},
	}

	proto := eventToProto(original)
	got := protoToEvent(proto)

	if got.ToolCall == nil {
		t.Fatal("expected ToolCall to be non-nil after roundtrip")
	}
	if got.ToolCall.ToolName != original.ToolCall.ToolName {
		t.Errorf("ToolName: got %q, want %q", got.ToolCall.ToolName, original.ToolCall.ToolName)
	}
	if got.ToolCall.RetryCount != original.ToolCall.RetryCount {
		t.Errorf("RetryCount: got %d, want %d", got.ToolCall.RetryCount, original.ToolCall.RetryCount)
	}
}

func TestEventTypeConversions(t *testing.T) {
	testCases := []types.EventType{
		types.EventPrompt, types.EventResponse, types.EventToolCall,
		types.EventToolResult, types.EventMemoryRead, types.EventMemoryWrite,
		types.EventReasoningStep, types.EventError, types.EventRetry, types.EventMetadata,
	}
	for _, et := range testCases {
		proto := eventTypeToProto(et)
		got := protoToEventType(proto)
		if got != et {
			t.Errorf("EventType %q: roundtrip got %q", et, got)
		}
	}
}

func TestSeverityConversions(t *testing.T) {
	testCases := []types.Severity{
		types.SeverityDebug, types.SeverityInfo, types.SeverityWarning,
		types.SeverityError, types.SeverityCritical,
	}
	for _, sv := range testCases {
		proto := severityToProto(sv)
		got := protoToSeverity(proto)
		if got != sv {
			t.Errorf("Severity %q: roundtrip got %q", sv, got)
		}
	}
}

// ── circuit breaker tests ─────────────────────────────────────────────────────

func TestCircuitBreaker_StartsClosedAndAllows(t *testing.T) {
	f := newForwarder()
	if !f.circuitAllows() {
		t.Fatal("circuit should start closed (allows requests)")
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	f := &AnalysisForwarder{
		cfg: AnalysisConfig{
			BatchSize:               10,
			FlushInterval:           time.Minute,
			CircuitBreakerThreshold: 3,
			CircuitBreakerCooldown:  100 * time.Millisecond,
		},
		logger:  slog.Default(),
		eventCh: make(chan *types.Event, 10),
	}

	f.recordFailure()
	f.recordFailure()
	if !f.circuitAllows() {
		t.Fatal("circuit should still be closed after 2 failures (threshold=3)")
	}

	f.recordFailure() // hits threshold
	if f.circuitAllows() {
		t.Fatal("circuit should be open after 3 failures")
	}

	// Wait for cooldown.
	time.Sleep(150 * time.Millisecond)
	if !f.circuitAllows() {
		t.Fatal("circuit should reset after cooldown expires")
	}
}

func TestCircuitBreaker_ResetsOnSuccess(t *testing.T) {
	f := newForwarder()

	f.recordFailure()
	f.recordFailure()
	f.recordSuccess()

	f.mu.Lock()
	failures := f.failures
	f.mu.Unlock()

	if failures != 0 {
		t.Fatalf("expected failures to reset to 0 after success, got %d", failures)
	}
}

func TestCircuitBreaker_SubmitDropsWhenFull(t *testing.T) {
	f := &AnalysisForwarder{
		cfg: AnalysisConfig{
			BatchSize:     10,
			FlushInterval: time.Minute,
		},
		logger:  slog.Default(),
		eventCh: make(chan *types.Event, 2), // tiny buffer
	}

	// Fill up the buffer.
	e := makeEvent(types.EventPrompt)
	f.Submit(e)
	f.Submit(e)

	// Third submit should not block or panic (drops silently).
	done := make(chan struct{})
	go func() {
		f.Submit(e)
		close(done)
	}()

	select {
	case <-done:
		// Good — submit returned without blocking.
	case <-time.After(time.Second):
		t.Fatal("Submit blocked instead of dropping on full buffer")
	}
}

// ── config loading tests ──────────────────────────────────────────────────────

func TestApplyDefaults_FillsZeroValues(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	if cfg.Server.ListenAddr != ":8443" {
		t.Errorf("ListenAddr default: got %q", cfg.Server.ListenAddr)
	}
	if cfg.Analysis.BatchSize != 50 {
		t.Errorf("BatchSize default: got %d", cfg.Analysis.BatchSize)
	}
	if cfg.Analysis.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval default: got %v", cfg.Analysis.FlushInterval)
	}
	if cfg.Analysis.CircuitBreakerThreshold != 5 {
		t.Errorf("CircuitBreakerThreshold default: got %d", cfg.Analysis.CircuitBreakerThreshold)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format default: got %q", cfg.Logging.Format)
	}
}

func TestApplyDefaults_DoesNotOverrideExisting(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{ListenAddr: ":9999"},
		Analysis: AnalysisConfig{
			BatchSize:               100,
			CircuitBreakerThreshold: 10,
		},
	}
	applyDefaults(cfg)

	if cfg.Server.ListenAddr != ":9999" {
		t.Errorf("expected existing ListenAddr to be preserved, got %q", cfg.Server.ListenAddr)
	}
	if cfg.Analysis.BatchSize != 100 {
		t.Errorf("expected existing BatchSize to be preserved, got %d", cfg.Analysis.BatchSize)
	}
}

func TestBuildLogger_JSON(t *testing.T) {
	l := buildLogger(LoggingConfig{Format: "json", Level: "info"})
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestBuildLogger_Text(t *testing.T) {
	l := buildLogger(LoggingConfig{Format: "text", Level: "debug"})
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}
