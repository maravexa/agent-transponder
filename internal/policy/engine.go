// Package policy defines the interface for authorization and rate limiting.
// The 0.1.0 implementation uses a YAML config file with static rules.
// The 1.0.0 implementation will use OPA (Open Policy Agent) with Rego policies.
package policy

import (
	"context"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/identity"
)

// Decision is the result of a policy evaluation.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionThrottle Decision = "throttle"
)

// EvalResult is returned by the policy engine for each request.
type EvalResult struct {
	Decision Decision
	Reason   string        // Human-readable explanation
	RetryAfter time.Duration // Non-zero if throttled
}

// Engine evaluates authorization and rate-limit policies.
// Implementations must be safe for concurrent use.
type Engine interface {
	// Evaluate checks whether the given agent is authorized to perform
	// the requested action. Rate limiting is also evaluated here.
	Evaluate(ctx context.Context, req EvalRequest) (*EvalResult, error)

	// Reload refreshes policy rules from the backing store.
	// For 0.1.0 this re-reads the YAML config. For 1.0.0 this is a no-op
	// because OPA handles its own bundle updates.
	Reload(ctx context.Context) error

	// Close releases resources.
	Close() error
}

// EvalRequest contains the information needed for a policy decision.
type EvalRequest struct {
	Agent    *identity.AgentIdentity
	Action   string // "ingest", "query", "export", "admin"
	Resource string // What is being accessed
}
