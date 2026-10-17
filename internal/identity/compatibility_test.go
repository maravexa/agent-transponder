package identity

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

// Legacy mapping is a fixture, never a runtime fallback: aliases must not be
// guessed because multiple certificate identities may have shared one directory.
func TestLegacyTenantMapping(t *testing.T) {
	cases := []struct {
		subject, legacy, exact string
		rejected               bool
	}{
		{"acme", "acme", "acme", false},
		{"Acme", "acme", "Acme", false},
		{"Acme Corp", "acme-corp", "Acme Corp", false},
		{"acme-corp", "acme-corp", "acme-corp", false},
		{"A  B", "a--b", "A  B", false},
		{"ÄCME", "äcme", "ÄCME", false},
		{"日本語", "日本語", "日本語", false},
		{"_DEFAULT", "_default", "_DEFAULT", false},
		{"_default", "_default", "_default", false},
		{" acme ", "acme", "", true},
		{"", "", "", true},
		{" ", "", "", true},
		{"../other", "../other", "", true},
		{"a/../b", "a/../b", "", true},
		{"a:b", "a:b", "", true},
		{"a\tb", "a\tb", "", true},
	}
	p := &TLSProvider{hmacKeys: map[string][]byte{"agent": []byte("key")}}
	for _, tc := range cases {
		t.Run(tc.subject, func(t *testing.T) {
			legacy := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(tc.subject)), " ", "-")
			if legacy != tc.legacy {
				t.Fatalf("legacy mapping %q", legacy)
			}
			cert := &x509.Certificate{DNSNames: []string{"agent"}, Subject: pkix.Name{Organization: []string{tc.subject}}}
			id, err := p.Identify(context.Background(), []*x509.Certificate{cert})
			if tc.rejected {
				if err == nil {
					t.Fatal("accepted unsafe legacy subject")
				}
				return
			}
			if err != nil || id.TenantID != tc.exact {
				t.Fatalf("identity: %v, %v", id, err)
			}
		})
	}
}
