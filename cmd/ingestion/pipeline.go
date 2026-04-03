package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/agent-transponder/agent-transponder/internal/audit"
	"github.com/agent-transponder/agent-transponder/internal/eventstore"
	"github.com/agent-transponder/agent-transponder/internal/identity"
	"github.com/agent-transponder/agent-transponder/internal/metrics"
	"github.com/agent-transponder/agent-transponder/internal/policy"
	"github.com/agent-transponder/agent-transponder/internal/redaction"
	"github.com/agent-transponder/agent-transponder/internal/types"
	pb "github.com/agent-transponder/agent-transponder/proto/agenttransponder/v1"
)

// knownEventTypes is the set of valid EventType values for schema validation.
var knownEventTypes = map[types.EventType]bool{
	types.EventPrompt:        true,
	types.EventResponse:      true,
	types.EventToolCall:      true,
	types.EventToolResult:    true,
	types.EventMemoryRead:    true,
	types.EventMemoryWrite:   true,
	types.EventReasoningStep: true,
	types.EventError:         true,
	types.EventRetry:         true,
	types.EventMetadata:      true,
}

// IngestionServer implements the gRPC EventIngestion service.
type IngestionServer struct {
	pb.UnimplementedEventIngestionServer

	idProvider identity.Provider
	store      eventstore.Store
	auditSink  audit.Sink
	policyEng  policy.Engine
	redactor   redaction.Redactor
	forwarder  *AnalysisForwarder
	collector  *metrics.Collector
	logger     *slog.Logger
	version    string
}

// IngestEvent processes a single event through the full ingestion pipeline.
func (s *IngestionServer) IngestEvent(ctx context.Context, req *pb.IngestEventRequest) (*pb.IngestEventResponse, error) {
	start := time.Now()

	if req.GetEvent() == nil {
		return &pb.IngestEventResponse{
			Accepted:        false,
			RejectionReason: "missing_event",
			Error:           "request contains no event",
		}, nil
	}

	// ── 1. Extract agent identity from the mTLS peer certificate ──────────
	agentID, tenantID, hmacKey, sourceIP, err := s.extractIdentity(ctx)
	if err != nil {
		s.logger.Warn("identity extraction failed", "err", err)
		s.collector.EventsRejected.WithLabelValues("identity_error").Inc()
		return &pb.IngestEventResponse{
			Accepted:        false,
			RejectionReason: "identity_error",
			Error:           err.Error(),
		}, nil
	}

	agentIdent := &identity.AgentIdentity{
		AgentID:  agentID,
		TenantID: tenantID,
		HMACKey:  hmacKey,
	}

	// ── 2. Policy evaluation — rate limiting and access control ────────────
	policyResult, err := s.policyEng.Evaluate(ctx, policy.EvalRequest{
		Agent:    agentIdent,
		Action:   "ingest",
		Resource: "events",
	})
	if err != nil {
		s.logger.Error("policy evaluation error", "agent_id", agentID, "err", err)
		s.collector.EventsRejected.WithLabelValues("policy_error").Inc()
		return &pb.IngestEventResponse{
			Accepted:        false,
			RejectionReason: "policy_error",
			Error:           "policy evaluation failed",
		}, nil
	}

	switch policyResult.Decision {
	case policy.DecisionDeny:
		s.logger.Info("event denied by policy",
			"agent_id", agentID, "reason", policyResult.Reason)
		_ = s.logAudit(ctx, audit.ActionAccessDenied, audit.OutcomeDenied,
			agentID, "events", policyResult.Reason, sourceIP)
		s.collector.EventsRejected.WithLabelValues("policy_denied").Inc()
		return &pb.IngestEventResponse{
			Accepted:        false,
			RejectionReason: "policy_denied",
			Error:           policyResult.Reason,
		}, nil

	case policy.DecisionThrottle:
		s.collector.ThrottledRequests.WithLabelValues(agentID).Inc()
		s.collector.EventsRejected.WithLabelValues("rate_limited").Inc()
		return &pb.IngestEventResponse{
			Accepted:        false,
			RejectionReason: "rate_limited",
			Error:           fmt.Sprintf("rate limited, retry after %s", policyResult.RetryAfter),
		}, status.Errorf(codes.ResourceExhausted, "rate limited")
	}

	// ── 3. Convert proto event → internal type ─────────────────────────────
	event := protoToEvent(req.GetEvent())
	event.AgentID = agentID   // Enforce identity from cert, not payload
	event.TenantID = tenantID

	// ── 4. Verify HMAC integrity ────────────────────────────────────────────
	if len(hmacKey) > 0 {
		ok, err := event.VerifyHMAC(hmacKey)
		if err != nil {
			s.logger.Warn("HMAC verification error", "event_id", event.ID, "err", err)
			s.collector.EventsRejected.WithLabelValues("hmac_error").Inc()
			return &pb.IngestEventResponse{
				Accepted:        false,
				RejectionReason: "hmac_error",
				Error:           "HMAC verification failed",
			}, nil
		}
		if !ok {
			s.logger.Warn("invalid HMAC", "event_id", event.ID, "agent_id", agentID)
			s.collector.EventsRejected.WithLabelValues("invalid_hmac").Inc()
			_ = s.logAudit(ctx, audit.ActionIngestEvent, audit.OutcomeDenied,
				agentID, event.ID, "HMAC mismatch", sourceIP)
			return &pb.IngestEventResponse{
				Accepted:        false,
				RejectionReason: "invalid_hmac",
				Error:           "HMAC signature mismatch",
			}, nil
		}
	}

	// ── 5. Schema validation ────────────────────────────────────────────────
	if err := validateEvent(event); err != nil {
		s.logger.Warn("schema validation failed", "event_id", event.ID, "err", err)
		s.collector.EventsRejected.WithLabelValues("schema_violation").Inc()
		return &pb.IngestEventResponse{
			Accepted:        false,
			RejectionReason: "schema_violation",
			Error:           err.Error(),
		}, nil
	}

	// ── 6. Redact sensitive content before persistence ─────────────────────
	redactedFields := s.redactor.Redact(event)

	// ── 7. Stamp server-side metadata ──────────────────────────────────────
	event.ReceivedAt = time.Now().UTC()
	event.RedactedFields = redactedFields

	// ── 8. Persist to event store ──────────────────────────────────────────
	storageKey, err := s.store.Append(ctx, event)
	if err != nil {
		s.logger.Error("event store append failed", "event_id", event.ID, "err", err)
		s.collector.EventsRejected.WithLabelValues("store_error").Inc()
		return nil, status.Errorf(codes.Internal, "failed to persist event")
	}

	// ── 9. Write to audit log ──────────────────────────────────────────────
	_ = s.logAudit(ctx, audit.ActionIngestEvent, audit.OutcomeSuccess,
		agentID, storageKey, fmt.Sprintf("event_type=%s", event.Type), sourceIP)

	// ── 10. Forward to analysis engine (non-blocking) ─────────────────────
	s.forwarder.Submit(event)

	// ── 11. Record metrics ─────────────────────────────────────────────────
	s.collector.EventsIngested.WithLabelValues(tenantID, string(event.Type)).Inc()
	s.collector.IngestLatency.WithLabelValues(tenantID).Observe(time.Since(start).Seconds())

	s.logger.Debug("event ingested",
		"event_id", event.ID,
		"agent_id", agentID,
		"tenant_id", tenantID,
		"type", event.Type,
		"storage_key", storageKey,
		"redacted_fields", len(redactedFields),
		"latency_ms", time.Since(start).Milliseconds())

	return &pb.IngestEventResponse{
		Accepted: true,
		EventId:  event.ID,
	}, nil
}

// IngestEventStream processes a client-streaming batch of events.
func (s *IngestionServer) IngestEventStream(
	stream pb.EventIngestion_IngestEventStreamServer,
) error {
	var accepted, rejected int64
	var errs []string

	for {
		req, err := stream.Recv()
		if err != nil {
			break
		}

		resp, _ := s.IngestEvent(stream.Context(), req)
		if resp != nil && resp.Accepted {
			accepted++
		} else {
			rejected++
			if resp != nil && resp.Error != "" {
				errs = append(errs, resp.Error)
			}
		}
	}

	return stream.SendAndClose(&pb.IngestEventStreamResponse{
		AcceptedCount: accepted,
		RejectedCount: rejected,
		Errors:        errs,
	})
}

// Ping verifies connectivity and echoes the caller's identity.
func (s *IngestionServer) Ping(ctx context.Context, _ *pb.PingRequest) (*pb.PingResponse, error) {
	agentID, _, _, _, err := s.extractIdentity(ctx)
	if err != nil {
		agentID = "unknown"
	}

	return &pb.PingResponse{
		Version:       s.version,
		ServerTime:    timestamppb.Now(),
		AgentIdentity: agentID,
	}, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// extractIdentity pulls the agent identity from the mTLS peer info.
func (s *IngestionServer) extractIdentity(ctx context.Context) (agentID, tenantID string, hmacKey []byte, sourceIP string, err error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", "", nil, "", fmt.Errorf("no peer info in context")
	}

	if p.Addr != nil {
		host, _, splitErr := net.SplitHostPort(p.Addr.String())
		if splitErr == nil {
			sourceIP = host
		} else {
			sourceIP = p.Addr.String()
		}
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", "", nil, sourceIP, fmt.Errorf("peer has no TLS auth info")
	}

	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return "", "", nil, sourceIP, fmt.Errorf("no client certificate presented")
	}

	agentIdent, err := s.idProvider.Identify(ctx, certs)
	if err != nil {
		return "", "", nil, sourceIP, fmt.Errorf("identify: %w", err)
	}

	return agentIdent.AgentID, agentIdent.TenantID, agentIdent.HMACKey, sourceIP, nil
}

// validateEvent checks that the event has required fields and a known type.
func validateEvent(e *types.Event) error {
	if e.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if e.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if e.Type == "" {
		return fmt.Errorf("event type is required")
	}
	if !knownEventTypes[e.Type] {
		return fmt.Errorf("unknown event type %q", e.Type)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	return nil
}

// logAudit writes an audit entry, logging (but not returning) any write error.
func (s *IngestionServer) logAudit(
	ctx context.Context,
	action audit.ActionType,
	outcome audit.Outcome,
	actorID, resource, detail, sourceIP string,
) error {
	err := s.auditSink.Log(ctx, audit.Entry{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Outcome:   outcome,
		ActorID:   actorID,
		Resource:  resource,
		Detail:    detail,
		SourceIP:  sourceIP,
	})
	if err != nil {
		s.logger.Error("audit log write failed", "action", action, "err", err)
	}
	s.collector.AuditEntriesTotal.Inc()
	return err
}

// peerCerts extracts the peer certificates from a context (used in tests).
func peerCerts(ctx context.Context) []*x509.Certificate {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return tlsInfo.State.PeerCertificates
}
