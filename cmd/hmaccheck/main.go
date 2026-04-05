// hmaccheck prints the canonical JSON used for HMAC computation for a fixed
// test event. Run this to verify that Go and Python produce identical output:
//
//	go run ./cmd/hmaccheck/
//
// The output must match what the Python SDK's _canonical_json() produces for
// the same event. If they differ, the HMAC will never verify across languages.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/types"
)

func main() {
	e := types.Event{
		ID:        "test-123",
		SessionID: "sess-1",
		AgentID:   "sdk-demo",
		TenantID:  "demo",
		Type:      types.EventPrompt,
		Severity:  types.SeverityInfo,
		// Zero time — matches datetime(1, 1, 1, tzinfo=timezone.utc) in Python
		Timestamp:  time.Time{},
		ReceivedAt: time.Time{},
	}

	// Replicate ComputeHMAC's canonical JSON logic (minus the actual signing)
	// so we can inspect what goes into the HMAC.
	savedHMAC := e.HMAC
	e.HMAC = ""
	defer func() { e.HMAC = savedHMAC }()

	raw, err := json.Marshal(&e)
	if err != nil {
		panic(err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	delete(m, "hmac") // Exclude hmac field — matches Python's include_hmac=False

	canonical, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(canonical))
}
