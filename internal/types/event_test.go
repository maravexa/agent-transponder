package types

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// TestComputeHMACSortedKeys verifies that ComputeHMAC produces the same digest
// as manually computing HMAC-SHA256 over alphabetically-sorted JSON keys.
// This ensures cross-language compatibility with the Python SDK which uses
// json.dumps(sort_keys=True) as its canonical form.
func TestComputeHMACSortedKeys(t *testing.T) {
	key := []byte("test-hmac-key")

	ts := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	e := &Event{
		ID:        "event-001",
		SessionID: "session-abc",
		AgentID:   "agent-xyz",
		TenantID:  "tenant-demo",
		Type:      EventPrompt,
		Severity:  SeverityInfo,
		Timestamp: ts,
		Prompt: &PromptData{
			Content: "Hello, world!",
			Role:    "user",
		},
	}

	got, err := e.ComputeHMAC(key)
	if err != nil {
		t.Fatalf("ComputeHMAC error: %v", err)
	}

	// Build the expected sorted JSON manually: marshal to struct,
	// round-trip through a map so keys are sorted, then recompute.
	saved := e.HMAC
	e.HMAC = ""
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	e.HMAC = saved

	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	delete(m, "hmac") // Must match ComputeHMAC which excludes the hmac field
	sorted, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("sorted json.Marshal error: %v", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(sorted)
	want := hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Errorf("HMAC mismatch:\n  got:  %s\n  want: %s", got, want)
	}
}

// TestVerifyHMAC checks that VerifyHMAC accepts a correctly-signed event
// and rejects a tampered one.
func TestVerifyHMAC(t *testing.T) {
	key := []byte("verify-key")

	e := &Event{
		ID:        "event-verify",
		SessionID: "session-v",
		AgentID:   "agent-v",
		TenantID:  "tenant-v",
		Type:      EventToolCall,
		Severity:  SeverityWarning,
		Timestamp: time.Now().UTC(),
	}

	sig, err := e.ComputeHMAC(key)
	if err != nil {
		t.Fatalf("ComputeHMAC error: %v", err)
	}
	e.HMAC = sig

	ok, err := e.VerifyHMAC(key)
	if err != nil {
		t.Fatalf("VerifyHMAC error: %v", err)
	}
	if !ok {
		t.Error("VerifyHMAC returned false for a correctly signed event")
	}

	// Tamper with the event — verification must fail.
	e.AgentID = "attacker"
	ok, err = e.VerifyHMAC(key)
	if err != nil {
		t.Fatalf("VerifyHMAC (tampered) error: %v", err)
	}
	if ok {
		t.Error("VerifyHMAC returned true for a tampered event")
	}
}
