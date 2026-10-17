package types

import "testing"

func TestTenantID(t *testing.T) {
	for _, id := range []string{string([]byte{0xff}), "", ".", "..", "../other", "/absolute", "a/b", `a\b`, `C:\tenant`, "a/../b", " padded", "trailing ", "a\x00b", "a\nb"} {
		if ValidateTenantID(id) == nil {
			t.Errorf("accepted unsafe ID %q", id)
		}
	}
	for _, id := range []string{"_default", "Acme", "tenant-01", "a_b", "a.b", "Acme Corp", "日本語"} {
		if err := ValidateTenantID(id); err != nil {
			t.Errorf("rejected legitimate ID %q: %v", id, err)
		}
	}
}
