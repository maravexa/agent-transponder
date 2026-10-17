package identity

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestCertificateTenantIdentity(t *testing.T) {
	p := &TLSProvider{hmacKeys: map[string][]byte{"agent": []byte("key")}}
	for _, tenant := range []string{"Acme Corp", "Tenant.A", "../escape", "/absolute", `a\b`, ".", "..", ""} {
		t.Run(tenant, func(t *testing.T) {
			cert := &x509.Certificate{DNSNames: []string{"agent"}, Subject: pkix.Name{Organization: []string{tenant}}}
			id, err := p.Identify(context.Background(), []*x509.Certificate{cert})
			if tenant == "Acme Corp" || tenant == "Tenant.A" {
				if err != nil || id.TenantID != tenant {
					t.Fatalf("identity rewritten: %v %v", id, err)
				}
			} else if err == nil {
				t.Fatal("unsafe certificate tenant accepted")
			}
		})
	}
	id, err := p.Identify(context.Background(), []*x509.Certificate{{DNSNames: []string{"agent"}}})
	if err != nil || id.TenantID != "_default" {
		t.Fatal(id, err)
	}
}
