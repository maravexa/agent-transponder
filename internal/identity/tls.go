package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
)

// TLSProvider is the 0.1.0 IdentityProvider implementation.
// It uses a self-signed CA to validate client certificates and
// extracts agent identity from the certificate's SAN (Subject Alternative Name).
type TLSProvider struct {
	caPool   *x509.CertPool
	cert     tls.Certificate
	hmacKeys map[string][]byte // agentID -> HMAC key
	mu       sync.RWMutex
}

// TLSProviderConfig holds the paths and keys needed for the TLS provider.
type TLSProviderConfig struct {
	CAPath   string            // Path to CA certificate PEM
	CertPath string            // Path to server certificate PEM
	KeyPath  string            // Path to server private key PEM
	HMACKeys map[string][]byte // AgentID -> HMAC key mapping
}

// NewTLSProvider creates a provider that validates client certs against a local CA.
func NewTLSProvider(cfg TLSProviderConfig) (*TLSProvider, error) {
	caPEM, err := os.ReadFile(cfg.CAPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	return &TLSProvider{
		caPool:   caPool,
		cert:     cert,
		hmacKeys: cfg.HMACKeys,
	}, nil
}

// TLSConfig returns the mTLS configuration for the ingestion server.
func (p *TLSProvider) TLSConfig() (*tls.Config, error) {
	return &tls.Config{
		Certificates: []tls.Certificate{p.cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.caPool,
		MinVersion:   tls.VersionTLS13, // TLS 1.3 only — no negotiation downgrade
	}, nil
}

// Identify extracts agent identity from the verified client certificate.
// The agent ID comes from the first DNS SAN. The tenant ID comes from the
// certificate's Organization (O) field.
func (p *TLSProvider) Identify(ctx context.Context, certs []*x509.Certificate) (*AgentIdentity, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no client certificate presented")
	}

	leaf := certs[0]

	// Extract agent ID from SAN
	agentID := ""
	if len(leaf.DNSNames) > 0 {
		agentID = leaf.DNSNames[0]
	} else if leaf.Subject.CommonName != "" {
		agentID = leaf.Subject.CommonName
	}

	if agentID == "" {
		return nil, fmt.Errorf("certificate has no identifiable SAN or CN")
	}

	// Extract tenant from Organization field
	tenantID := "_default"
	if len(leaf.Subject.Organization) > 0 {
		tenantID = sanitizeIdentifier(leaf.Subject.Organization[0])
	}

	// Look up HMAC key
	p.mu.RLock()
	hmacKey, ok := p.hmacKeys[agentID]
	p.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no HMAC key registered for agent %q", agentID)
	}

	return &AgentIdentity{
		AgentID:  agentID,
		TenantID: tenantID,
		HMACKey:  hmacKey,
		Raw:      leaf.Subject.String(),
	}, nil
}

// LookupHMACKey returns the HMAC key for a known agent.
func (p *TLSProvider) LookupHMACKey(ctx context.Context, agentID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	key, ok := p.hmacKeys[agentID]
	if !ok {
		return nil, fmt.Errorf("unknown agent: %s", agentID)
	}
	return key, nil
}

// Close is a no-op for the static TLS provider.
// The 1.0.0 SPIRE implementation will close the workload API connection.
func (p *TLSProvider) Close() error {
	return nil
}

// sanitizeIdentifier cleans a string for use as a tenant/agent ID.
func sanitizeIdentifier(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "-")
	return s
}
