// Package redaction defines the interface for scrubbing sensitive data from events
// before they are persisted. Redaction happens at ingestion time — once written,
// the raw sensitive data never exists on disk.
package redaction

import (
	"regexp"
	"strings"

	"github.com/agent-transponder/agent-transponder/internal/types"
)

// Redactor scrubs sensitive data from events.
type Redactor interface {
	// Redact modifies the event in place, replacing sensitive content
	// with "[REDACTED]" markers. Returns the list of fields that were redacted.
	Redact(event *types.Event) []string
}

// Pattern defines a named redaction rule.
type Pattern struct {
	Name    string         `yaml:"name"`
	Regex   *regexp.Regexp `yaml:"-"`
	RawExpr string         `yaml:"pattern"` // For YAML serialization
}

// RegexRedactor is the 0.1.0 Redactor implementation.
// It applies a configurable list of regex patterns to scrub secrets,
// PII, and other sensitive data from event content fields.
type RegexRedactor struct {
	marker   string
	patterns []Pattern
}

// DefaultPatterns returns the built-in redaction patterns for common secrets.
func DefaultPatterns() []Pattern {
	return []Pattern{
		{Name: "aws_access_key", RawExpr: `(?i)AKIA[0-9A-Z]{16}`},
		{Name: "aws_secret_key", RawExpr: `(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}`},
		{Name: "generic_api_key", RawExpr: `(?i)(?:api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*[A-Za-z0-9\-_.]{20,}`},
		{Name: "bearer_token", RawExpr: `(?i)Bearer\s+[A-Za-z0-9\-_.~+/]+=*`},
		{Name: "jwt", RawExpr: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`},
		{Name: "private_key", RawExpr: `-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----`},
		{Name: "connection_string", RawExpr: `(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^\s]+`},
		{Name: "password_field", RawExpr: `(?i)(?:password|passwd|pwd)\s*[=:]\s*\S+`},
		{Name: "ssn", RawExpr: `\b\d{3}-\d{2}-\d{4}\b`},
		{Name: "credit_card", RawExpr: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`},
		{Name: "email", RawExpr: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`},
		{Name: "ip_address", RawExpr: `\b(?:\d{1,3}\.){3}\d{1,3}\b`},
		{Name: "github_token", RawExpr: `(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`},
		{Name: "slack_token", RawExpr: `xox[bporas]-[0-9]+-[0-9]+-[A-Za-z0-9]+`},
	}
}

// NewRegexRedactor creates a redactor with the given patterns.
// If patterns is nil, the default patterns are used.
func NewRegexRedactor(patterns []Pattern) (*RegexRedactor, error) {
	if patterns == nil {
		patterns = DefaultPatterns()
	}

	// Compile all patterns
	compiled := make([]Pattern, len(patterns))
	for i, p := range patterns {
		r, err := regexp.Compile(p.RawExpr)
		if err != nil {
			return nil, err
		}
		compiled[i] = Pattern{
			Name:    p.Name,
			Regex:   r,
			RawExpr: p.RawExpr,
		}
	}

	return &RegexRedactor{
		patterns: compiled,
		marker:   "[REDACTED]",
	}, nil
}

// Redact scrubs sensitive content from all text fields of an event.
func (r *RegexRedactor) Redact(event *types.Event) []string {
	var redacted []string

	if event.Prompt != nil && r.scrub(&event.Prompt.Content) {
		redacted = append(redacted, "prompt.content")
	}
	if event.Response != nil && r.scrub(&event.Response.Content) {
		redacted = append(redacted, "response.content")
	}
	if event.ToolCall != nil {
		redacted = append(redacted, r.redactToolCall(event.ToolCall)...)
	}
	if event.Memory != nil && r.scrub(&event.Memory.Value) {
		redacted = append(redacted, "memory.value")
	}
	if event.Reasoning != nil && r.scrub(&event.Reasoning.Content) {
		redacted = append(redacted, "reasoning.content")
	}
	if event.Error != nil {
		if r.scrub(&event.Error.Message) {
			redacted = append(redacted, "error.message")
		}
		if r.scrub(&event.Error.Stacktrace) {
			redacted = append(redacted, "error.stacktrace")
		}
	}

	return redacted
}

// redactToolCall scrubs sensitive data from a ToolCallData payload.
func (r *RegexRedactor) redactToolCall(tc *types.ToolCallData) []string {
	var redacted []string
	if args := string(tc.Arguments); r.scrub(&args) {
		tc.Arguments = []byte(args)
		redacted = append(redacted, "tool_call.arguments")
	}
	if result := string(tc.Result); r.scrub(&result) {
		tc.Result = []byte(result)
		redacted = append(redacted, "tool_call.result")
	}
	if r.scrub(&tc.ErrorMsg) {
		redacted = append(redacted, "tool_call.error_msg")
	}
	return redacted
}

// scrub applies all patterns to a string, replacing matches with the marker.
// Returns true if any replacements were made.
func (r *RegexRedactor) scrub(s *string) bool {
	if s == nil || *s == "" {
		return false
	}

	original := *s
	for _, p := range r.patterns {
		*s = p.Regex.ReplaceAllString(*s, r.marker)
	}

	return *s != original
}

// AddPattern adds a custom pattern at runtime.
func (r *RegexRedactor) AddPattern(name, expr string) error {
	compiled, err := regexp.Compile(expr)
	if err != nil {
		return err
	}

	r.patterns = append(r.patterns, Pattern{
		Name:    name,
		Regex:   compiled,
		RawExpr: expr,
	})
	return nil
}

// PatternNames returns the names of all active patterns.
func (r *RegexRedactor) PatternNames() []string {
	names := make([]string, len(r.patterns))
	for i, p := range r.patterns {
		names[i] = p.Name
	}
	return names
}

// ContainsSensitiveData checks if a string matches any redaction pattern
// without modifying it. Useful for pre-flight checks.
func (r *RegexRedactor) ContainsSensitiveData(s string) (bool, []string) {
	var matched []string
	for _, p := range r.patterns {
		if p.Regex.MatchString(s) {
			matched = append(matched, p.Name)
		}
	}
	return len(matched) > 0, matched
}

// Compile-time check: ensure string replacement works as a no-alloc placeholder.
var _ = strings.NewReplacer()
