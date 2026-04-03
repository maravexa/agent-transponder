package policy

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigEngine is the 0.1.0 PolicyEngine implementation.
// It loads rules from a YAML config file and enforces token-bucket rate limiting.
type ConfigEngine struct {
	mu         sync.RWMutex
	configPath string
	rules      PolicyRules
	buckets    map[string]*tokenBucket // agentID -> bucket
}

// PolicyRules is the YAML-serializable policy configuration.
type PolicyRules struct {
	DefaultRateLimit RateLimitConfig            `yaml:"default_rate_limit"`
	AgentOverrides   map[string]RateLimitConfig `yaml:"agent_overrides"`
	AllowedActions   map[string][]string        `yaml:"allowed_actions"` // agentID -> actions
	DenyList         []string                   `yaml:"deny_list"`       // Blocked agent IDs
}

// RateLimitConfig defines the token bucket parameters.
type RateLimitConfig struct {
	EventsPerSecond float64 `yaml:"events_per_second"`
	BurstSize       int     `yaml:"burst_size"`
}

// NewConfigEngine creates a policy engine backed by a YAML config file.
func NewConfigEngine(configPath string) (*ConfigEngine, error) {
	e := &ConfigEngine{
		configPath: configPath,
		buckets:    make(map[string]*tokenBucket),
	}

	if err := e.Reload(context.Background()); err != nil {
		return nil, err
	}

	return e, nil
}

// Evaluate checks authorization and rate limits for a request.
func (e *ConfigEngine) Evaluate(ctx context.Context, req EvalRequest) (*EvalResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if req.Agent == nil {
		return &EvalResult{Decision: DecisionDeny, Reason: "no agent identity"}, nil
	}

	// Check deny list
	for _, denied := range e.rules.DenyList {
		if req.Agent.AgentID == denied {
			return &EvalResult{Decision: DecisionDeny, Reason: "agent is on deny list"}, nil
		}
	}

	// Check allowed actions (if configured for this agent)
	if allowed, ok := e.rules.AllowedActions[req.Agent.AgentID]; ok {
		actionAllowed := false
		for _, a := range allowed {
			if a == req.Action || a == "*" {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			return &EvalResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("agent %q not authorized for action %q", req.Agent.AgentID, req.Action),
			}, nil
		}
	}

	// Rate limiting
	bucket := e.getBucket(req.Agent.AgentID)
	if !bucket.allow() {
		retryAfter := bucket.retryAfter()
		return &EvalResult{
			Decision:   DecisionThrottle,
			Reason:     "rate limit exceeded",
			RetryAfter: retryAfter,
		}, nil
	}

	return &EvalResult{Decision: DecisionAllow}, nil
}

// Reload reads the policy config from disk.
func (e *ConfigEngine) Reload(ctx context.Context) error {
	data, err := os.ReadFile(e.configPath)
	if err != nil {
		return fmt.Errorf("read policy config: %w", err)
	}

	var rules PolicyRules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("parse policy config: %w", err)
	}

	// Apply defaults
	if rules.DefaultRateLimit.EventsPerSecond == 0 {
		rules.DefaultRateLimit.EventsPerSecond = 100
	}
	if rules.DefaultRateLimit.BurstSize == 0 {
		rules.DefaultRateLimit.BurstSize = 500
	}

	e.mu.Lock()
	e.rules = rules
	// Reset rate limit buckets on config reload
	e.buckets = make(map[string]*tokenBucket)
	e.mu.Unlock()

	return nil
}

// Close is a no-op for the config engine.
func (e *ConfigEngine) Close() error {
	return nil
}

// getBucket returns or creates a token bucket for an agent.
// Must be called with at least a read lock held.
func (e *ConfigEngine) getBucket(agentID string) *tokenBucket {
	if b, ok := e.buckets[agentID]; ok {
		return b
	}

	// Check for agent-specific override
	cfg := e.rules.DefaultRateLimit
	if override, ok := e.rules.AgentOverrides[agentID]; ok {
		cfg = override
	}

	b := newTokenBucket(cfg.EventsPerSecond, cfg.BurstSize)
	e.buckets[agentID] = b
	return b
}

// tokenBucket implements a simple token bucket rate limiter.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	rate     float64 // tokens per second
	lastFill time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:   float64(burst),
		max:      float64(burst),
		rate:     rate,
		lastFill: time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill()

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (b *tokenBucket) retryAfter() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rate <= 0 {
		return time.Second
	}
	return time.Duration(float64(time.Second) / b.rate)
}

func (b *tokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.lastFill = now
}
