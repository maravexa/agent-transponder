// Package identity defines the interface for workload identity verification.
// The 0.1.0 implementation validates X.509 client certs from a self-signed CA.
// The 1.0.0 implementation will validate SPIFFE SVIDs from a SPIRE server.
package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
)

// AgentIdentity represents the verified identity of a connecting agent.
type AgentIdentity struct {
	AgentID   string // Unique agent identifier (from cert SAN or SPIFFE ID)
	TenantID  string // Tenant this agent belongs to (from cert OU or SPIFFE trust domain)
	HMACKey   []byte // Per-agent key for event HMAC verification
	Raw       string // The raw identity string (cert SAN, SPIFFE URI, etc.)
}

// Provider validates inbound connections and extracts agent identity.
// Implementations must be safe for concurrent use.
type Provider interface {
	// TLSConfig returns the TLS configuration for the ingestion server.
	// This configures mTLS — both server cert and client cert verification.
	TLSConfig() (*tls.Config, error)

	// Identify extracts and validates the agent identity from a verified
	// TLS connection. Returns an error if the identity is invalid or
	// the agent is not authorized.
	Identify(ctx context.Context, certs []*x509.Certificate) (*AgentIdentity, error)

	// LookupHMACKey returns the HMAC key for the given agent.
	// Used during event verification when the agent identity is already known.
	LookupHMACKey(ctx context.Context, agentID string) ([]byte, error)

	// Close releases resources (e.g., file watchers, SPIRE connections).
	Close() error
}
