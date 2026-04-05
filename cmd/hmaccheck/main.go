// hmaccheck prints the canonical JSON and HMAC digest for an event.
//
// Default usage — built-in test event:
//
//	go run ./cmd/hmaccheck/
//
// Load event from JSON file:
//
//	go run ./cmd/hmaccheck/ --json event.json --key demo-hmac-key
//
// The canonical JSON output must match what the Python SDK's _canonical_json()
// produces for the same event. If they differ, the HMAC will never verify
// across languages.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"crypto/hmac"
	"crypto/sha256"

	"github.com/agent-transponder/agent-transponder/internal/types"
)

func main() {
	jsonFile := flag.String("json", "", "path to event JSON file; if omitted, a built-in test event is used")
	keyStr := flag.String("key", "demo-hmac-key", "HMAC key (string)")
	flag.Parse()

	var event types.Event

	if *jsonFile != "" {
		data, err := os.ReadFile(*jsonFile)
		if err != nil {
			log.Fatalf("read %s: %v", *jsonFile, err)
		}
		if err := json.Unmarshal(data, &event); err != nil {
			log.Fatalf("parse %s: %v", *jsonFile, err)
		}
	} else {
		// Built-in test event — matches the Python cross-language comparison snippet.
		event = types.Event{
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
	}

	key := []byte(*keyStr)
	canonical, digest := computeWithCanonical(&event, key)

	fmt.Println("--- canonical JSON ---")
	fmt.Println(string(canonical))
	fmt.Println("--- HMAC-SHA256 hex ---")
	fmt.Println(digest)
}

// computeWithCanonical replicates ComputeHMAC and also returns the canonical JSON
// so it can be printed for cross-language debugging.
func computeWithCanonical(e *types.Event, key []byte) (canonical []byte, digest string) {
	savedHMAC := e.HMAC
	e.HMAC = ""
	defer func() { e.HMAC = savedHMAC }()

	raw, err := json.Marshal(e)
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}

	var m map[string]interface{}
	err = json.Unmarshal(raw, &m)
	if err != nil {
		log.Fatalf("unmarshal for sort: %v", err)
	}
	delete(m, "hmac")

	canonical, err = json.Marshal(m)
	if err != nil {
		log.Fatalf("remarshal sorted: %v", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	digest = hex.EncodeToString(mac.Sum(nil))
	return canonical, digest
}
