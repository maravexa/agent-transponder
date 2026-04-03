package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/agent-transponder/agent-transponder/internal/types"
	pb "github.com/agent-transponder/agent-transponder/proto/agenttransponder/v1"
)

// circuitState represents the circuit breaker state.
type circuitState int

const (
	circuitClosed circuitState = iota // Normal — forwarding enabled.
	circuitOpen                       // Tripped — forwarding suspended.
)

// AnalysisForwarder buffers events and forwards them to the analysis engine
// in batches. All submit calls are non-blocking.
type AnalysisForwarder struct {
	cfg     AnalysisConfig
	logger  *slog.Logger
	conn    *grpc.ClientConn
	client  pb.AnalysisServiceClient
	eventCh chan *types.Event
	cancel  context.CancelFunc

	openUntil time.Time

	wg       sync.WaitGroup
	mu       sync.Mutex
	circuit  circuitState
	failures int
}

// NewAnalysisForwarder creates a forwarder. Connection failures at startup are
// logged as warnings — the forwarder will retry on the first flush.
func NewAnalysisForwarder(cfg AnalysisConfig, logger *slog.Logger) *AnalysisForwarder {
	f := &AnalysisForwarder{
		cfg:     cfg,
		logger:  logger,
		eventCh: make(chan *types.Event, 1000),
	}

	if err := f.dial(); err != nil {
		logger.Warn("analysis engine unavailable at startup, will retry on first flush",
			"addr", cfg.Addr, "err", err)
	}

	return f
}

// dial establishes the gRPC connection to the analysis engine.
func (f *AnalysisForwarder) dial() error {
	var opts []grpc.DialOption

	if f.cfg.TLSEnabled && f.cfg.CAPath != "" {
		creds, err := credentials.NewClientTLSFromFile(f.cfg.CAPath, "")
		if err != nil {
			return fmt.Errorf("load analysis tls credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(f.cfg.Addr, opts...)
	if err != nil {
		return fmt.Errorf("dial analysis engine %q: %w", f.cfg.Addr, err)
	}

	if f.conn != nil {
		_ = f.conn.Close()
	}
	f.conn = conn
	f.client = pb.NewAnalysisServiceClient(conn)
	return nil
}

// Start launches the background batching goroutine.
func (f *AnalysisForwarder) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel

	f.wg.Add(1)
	go f.runBatcher(ctx)
}

// Submit enqueues an event for forwarding. Non-blocking — drops if buffer full.
func (f *AnalysisForwarder) Submit(event *types.Event) {
	select {
	case f.eventCh <- event:
	default:
		f.logger.Warn("analysis forwarder buffer full, dropping event",
			"event_id", event.ID, "session_id", event.SessionID)
	}
}

// Stop signals the batcher to finish and waits for in-flight batches to drain.
func (f *AnalysisForwarder) Stop() {
	if f.cancel != nil {
		f.cancel()
	}
	f.wg.Wait()
	if f.conn != nil {
		_ = f.conn.Close()
	}
}

// runBatcher is the main batching loop.
func (f *AnalysisForwarder) runBatcher(ctx context.Context) {
	defer f.wg.Done()

	ticker := time.NewTicker(f.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]*types.Event, 0, f.cfg.BatchSize)

	for {
		select {
		case event := <-f.eventCh:
			batch = append(batch, event)
			if len(batch) >= f.cfg.BatchSize {
				f.flush(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				f.flush(batch)
				batch = batch[:0]
			}

		case <-ctx.Done():
			f.drainAndFlush(batch)
			return
		}
	}
}

// drainAndFlush empties any buffered events and sends the final batch on shutdown.
func (f *AnalysisForwarder) drainAndFlush(batch []*types.Event) {
	for {
		select {
		case event := <-f.eventCh:
			batch = append(batch, event)
		default:
			if len(batch) > 0 {
				f.flush(batch)
			}
			return
		}
	}
}

// flush sends a batch of events to the analysis engine, grouped by session.
func (f *AnalysisForwarder) flush(events []*types.Event) {
	if !f.circuitAllows() {
		f.logger.Debug("circuit breaker open, skipping analysis forward",
			"batch_size", len(events))
		return
	}

	// Reconnect if we lost the connection.
	if f.client == nil {
		if err := f.dial(); err != nil {
			f.logger.Error("analysis engine reconnect failed", "err", err)
			f.recordFailure()
			return
		}
	}

	// Group events by session so each batch has coherent context.
	sessions := make(map[string][]*types.Event)
	for _, e := range events {
		sessions[e.SessionID] = append(sessions[e.SessionID], e)
	}

	allOK := true
	for sessionID, sessionEvents := range sessions {
		if err := f.sendBatch(sessionID, sessionEvents); err != nil {
			f.logger.Error("analysis batch failed",
				"session_id", sessionID,
				"events", len(sessionEvents),
				"err", err)
			allOK = false
		}
	}

	if allOK {
		f.recordSuccess()
	} else {
		f.recordFailure()
	}
}

// sendBatch sends a single session's events to AnalyzeBatch.
func (f *AnalysisForwarder) sendBatch(sessionID string, events []*types.Event) error {
	if len(events) == 0 {
		return nil
	}

	protoEvents := make([]*pb.Event, 0, len(events))
	for _, e := range events {
		protoEvents = append(protoEvents, eventToProto(e))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := f.client.AnalyzeBatch(ctx, &pb.AnalyzeBatchRequest{
		SessionId: sessionID,
		AgentId:   events[0].AgentID,
		TenantId:  events[0].TenantID,
		Events:    protoEvents,
	})
	return err
}

// circuitAllows returns true if the circuit breaker permits a send attempt.
func (f *AnalysisForwarder) circuitAllows() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.circuit == circuitOpen {
		if time.Now().After(f.openUntil) {
			f.circuit = circuitClosed
			f.failures = 0
			f.logger.Info("circuit breaker reset, resuming analysis forwarding")
			return true
		}
		return false
	}
	return true
}

// recordFailure increments the failure counter and opens the circuit if threshold hit.
func (f *AnalysisForwarder) recordFailure() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.failures++
	if f.failures >= f.cfg.CircuitBreakerThreshold {
		f.circuit = circuitOpen
		f.openUntil = time.Now().Add(f.cfg.CircuitBreakerCooldown)
		f.logger.Warn("circuit breaker opened",
			"consecutive_failures", f.failures,
			"cooldown", f.cfg.CircuitBreakerCooldown)
	}
}

// recordSuccess resets the failure counter.
func (f *AnalysisForwarder) recordSuccess() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = 0
}

// ── proto conversion helpers ──────────────────────────────────────────────────

// eventToProto converts an internal Event to its protobuf representation.
func eventToProto(e *types.Event) *pb.Event {
	proto := &pb.Event{
		Id:        e.ID,
		SessionId: e.SessionID,
		AgentId:   e.AgentID,
		TenantId:  e.TenantID,
		Type:      eventTypeToProto(e.Type),
		Severity:  severityToProto(e.Severity),
		Timestamp: timestamppb.New(e.Timestamp),
		Duration:  durationpb.New(e.Duration),
		Model:     e.Model,
		Hmac:      e.HMAC,
		Labels:    e.Labels,
	}

	if e.Prompt != nil {
		proto.Prompt = &pb.PromptData{
			Content:    e.Prompt.Content,
			Role:       e.Prompt.Role,
			TokenCount: safeInt32(e.Prompt.TokenCount),
		}
	}
	if e.Response != nil {
		proto.Response = &pb.ResponseData{
			Content:      e.Response.Content,
			FinishReason: e.Response.FinishReason,
			TokenCount:   safeInt32(e.Response.TokenCount),
		}
	}
	if e.ToolCall != nil {
		tc := &pb.ToolCallData{
			ToolName:   e.ToolCall.ToolName,
			Success:    e.ToolCall.Success,
			ErrorMsg:   e.ToolCall.ErrorMsg,
			RetryCount: safeInt32(e.ToolCall.RetryCount),
		}
		if e.ToolCall.Arguments != nil {
			if s, err := jsonToStruct(e.ToolCall.Arguments); err == nil {
				tc.Arguments = s
			}
		}
		if e.ToolCall.Result != nil {
			if s, err := jsonToStruct(e.ToolCall.Result); err == nil {
				tc.Result = s
			}
		}
		proto.ToolCall = tc
	}
	if e.Memory != nil {
		proto.Memory = &pb.MemoryData{
			Operation: e.Memory.Operation,
			Key:       e.Memory.Key,
			Value:     e.Memory.Value,
		}
	}
	if e.Reasoning != nil {
		proto.Reasoning = &pb.ReasoningData{
			Step:    safeInt32(e.Reasoning.Step),
			Content: e.Reasoning.Content,
		}
	}
	if e.Error != nil {
		proto.Error = &pb.ErrorData{
			Code:       e.Error.Code,
			Message:    e.Error.Message,
			Stacktrace: e.Error.Stacktrace,
			Retryable:  e.Error.Retryable,
		}
	}
	if e.TokenUsage != nil {
		proto.TokenUsage = &pb.TokenUsage{
			PromptTokens:     safeInt32(e.TokenUsage.PromptTokens),
			CompletionTokens: safeInt32(e.TokenUsage.CompletionTokens),
			TotalTokens:      safeInt32(e.TokenUsage.TotalTokens),
		}
	}

	return proto
}

// protoToEvent converts a proto Event to the internal Event type.
func protoToEvent(p *pb.Event) *types.Event {
	e := &types.Event{
		ID:        p.GetId(),
		SessionID: p.GetSessionId(),
		AgentID:   p.GetAgentId(),
		TenantID:  p.GetTenantId(),
		Type:      protoToEventType(p.GetType()),
		Severity:  protoToSeverity(p.GetSeverity()),
		Timestamp: p.GetTimestamp().AsTime(),
		Duration:  p.GetDuration().AsDuration(),
		Model:     p.GetModel(),
		HMAC:      p.GetHmac(),
		Labels:    p.GetLabels(),
	}

	if pr := p.GetPrompt(); pr != nil {
		e.Prompt = &types.PromptData{
			Content:    pr.GetContent(),
			Role:       pr.GetRole(),
			TokenCount: int(pr.GetTokenCount()),
		}
	}
	if r := p.GetResponse(); r != nil {
		e.Response = &types.ResponseData{
			Content:      r.GetContent(),
			FinishReason: r.GetFinishReason(),
			TokenCount:   int(r.GetTokenCount()),
		}
	}
	if tc := p.GetToolCall(); tc != nil {
		tcd := &types.ToolCallData{
			ToolName:   tc.GetToolName(),
			Success:    tc.GetSuccess(),
			ErrorMsg:   tc.GetErrorMsg(),
			RetryCount: int(tc.GetRetryCount()),
		}
		if tc.Arguments != nil {
			if raw, err := structToJSON(tc.Arguments); err == nil {
				tcd.Arguments = raw
			}
		}
		if tc.Result != nil {
			if raw, err := structToJSON(tc.Result); err == nil {
				tcd.Result = raw
			}
		}
		e.ToolCall = tcd
	}
	if m := p.GetMemory(); m != nil {
		e.Memory = &types.MemoryData{
			Operation: m.GetOperation(),
			Key:       m.GetKey(),
			Value:     m.GetValue(),
		}
	}
	if r := p.GetReasoning(); r != nil {
		e.Reasoning = &types.ReasoningData{
			Step:    int(r.GetStep()),
			Content: r.GetContent(),
		}
	}
	if er := p.GetError(); er != nil {
		e.Error = &types.ErrorData{
			Code:       er.GetCode(),
			Message:    er.GetMessage(),
			Stacktrace: er.GetStacktrace(),
			Retryable:  er.GetRetryable(),
		}
	}
	if tu := p.GetTokenUsage(); tu != nil {
		e.TokenUsage = &types.TokenUsage{
			PromptTokens:     int(tu.GetPromptTokens()),
			CompletionTokens: int(tu.GetCompletionTokens()),
			TotalTokens:      int(tu.GetTotalTokens()),
		}
	}

	return e
}

func eventTypeToProto(t types.EventType) pb.EventType {
	switch t {
	case types.EventPrompt:
		return pb.EventType_EVENT_TYPE_PROMPT
	case types.EventResponse:
		return pb.EventType_EVENT_TYPE_RESPONSE
	case types.EventToolCall:
		return pb.EventType_EVENT_TYPE_TOOL_CALL
	case types.EventToolResult:
		return pb.EventType_EVENT_TYPE_TOOL_RESULT
	case types.EventMemoryRead:
		return pb.EventType_EVENT_TYPE_MEMORY_READ
	case types.EventMemoryWrite:
		return pb.EventType_EVENT_TYPE_MEMORY_WRITE
	case types.EventReasoningStep:
		return pb.EventType_EVENT_TYPE_REASONING_STEP
	case types.EventError:
		return pb.EventType_EVENT_TYPE_ERROR
	case types.EventRetry:
		return pb.EventType_EVENT_TYPE_RETRY
	case types.EventMetadata:
		return pb.EventType_EVENT_TYPE_METADATA
	default:
		return pb.EventType_EVENT_TYPE_UNSPECIFIED
	}
}

func protoToEventType(t pb.EventType) types.EventType {
	switch t {
	case pb.EventType_EVENT_TYPE_PROMPT:
		return types.EventPrompt
	case pb.EventType_EVENT_TYPE_RESPONSE:
		return types.EventResponse
	case pb.EventType_EVENT_TYPE_TOOL_CALL:
		return types.EventToolCall
	case pb.EventType_EVENT_TYPE_TOOL_RESULT:
		return types.EventToolResult
	case pb.EventType_EVENT_TYPE_MEMORY_READ:
		return types.EventMemoryRead
	case pb.EventType_EVENT_TYPE_MEMORY_WRITE:
		return types.EventMemoryWrite
	case pb.EventType_EVENT_TYPE_REASONING_STEP:
		return types.EventReasoningStep
	case pb.EventType_EVENT_TYPE_ERROR:
		return types.EventError
	case pb.EventType_EVENT_TYPE_RETRY:
		return types.EventRetry
	case pb.EventType_EVENT_TYPE_METADATA:
		return types.EventMetadata
	default:
		return ""
	}
}

func severityToProto(s types.Severity) pb.Severity {
	switch s {
	case types.SeverityDebug:
		return pb.Severity_SEVERITY_DEBUG
	case types.SeverityInfo:
		return pb.Severity_SEVERITY_INFO
	case types.SeverityWarning:
		return pb.Severity_SEVERITY_WARNING
	case types.SeverityError:
		return pb.Severity_SEVERITY_ERROR
	case types.SeverityCritical:
		return pb.Severity_SEVERITY_CRITICAL
	default:
		return pb.Severity_SEVERITY_UNSPECIFIED
	}
}

func protoToSeverity(s pb.Severity) types.Severity {
	switch s {
	case pb.Severity_SEVERITY_DEBUG:
		return types.SeverityDebug
	case pb.Severity_SEVERITY_INFO:
		return types.SeverityInfo
	case pb.Severity_SEVERITY_WARNING:
		return types.SeverityWarning
	case pb.Severity_SEVERITY_ERROR:
		return types.SeverityError
	case pb.Severity_SEVERITY_CRITICAL:
		return types.SeverityCritical
	default:
		return ""
	}
}

// jsonToStruct converts a json.RawMessage to a protobuf Struct.
func jsonToStruct(raw json.RawMessage) (*structpb.Struct, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return structpb.NewStruct(m)
}

// structToJSON converts a protobuf Struct to json.RawMessage.
func structToJSON(s *structpb.Struct) (json.RawMessage, error) {
	b, err := s.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// safeInt32 converts an int to int32, clamping to avoid overflow.
func safeInt32(n int) int32 {
	const maxInt32 = 1<<31 - 1
	if n > maxInt32 {
		return maxInt32
	}
	if n < -1<<31 {
		return -1 << 31
	}
	return int32(n) //nolint:gosec
}
