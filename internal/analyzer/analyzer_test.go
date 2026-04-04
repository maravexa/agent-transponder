package analyzer_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/analyzer"
	"github.com/agent-transponder/agent-transponder/internal/analyzer/detectors"
	"github.com/agent-transponder/agent-transponder/internal/types"
)

// writeEventFile writes events as JSONL to path.
func writeEventFile(t *testing.T, path string, events []*types.Event) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
}

// readFindings collects all Finding objects from JSONL files in dir.
func readFindings(t *testing.T, dir string) []analyzer.Finding {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var findings []analyzer.Finding
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".jsonl" {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var finding analyzer.Finding
			if err := json.Unmarshal(scanner.Bytes(), &finding); err != nil {
				continue
			}
			findings = append(findings, finding)
		}
		_ = f.Close()
	}
	return findings
}

func newTestConfig(eventsDir, findingsDir string) *analyzer.Config {
	return &analyzer.Config{
		Events:   analyzer.EventsConfig{Path: eventsDir, PollInterval: 100 * time.Millisecond},
		Findings: analyzer.FindingsConfig{Path: findingsDir},
		Listen:   analyzer.ListenConfig{Address: "127.0.0.1", Port: 18420},
		Logging:  analyzer.LoggingConfig{Level: "debug"},
	}
}

func makeToolEvent(id, sessionID, toolName string, ts time.Time) *types.Event {
	return &types.Event{
		ID:        id,
		SessionID: sessionID,
		AgentID:   "agent-test",
		TenantID:  "tenant-test",
		Type:      types.EventToolCall,
		Severity:  types.SeverityInfo,
		Timestamp: ts,
		ToolCall: &types.ToolCallData{
			ToolName: toolName,
			Success:  true,
		},
	}
}

// TestAnalyzer_EndToEnd: writes JSONL events, runs one poll, checks findings.
func TestAnalyzer_EndToEnd(t *testing.T) {
	eventsDir := t.TempDir()
	findingsDir := t.TempDir()

	cfg := newTestConfig(eventsDir, findingsDir)
	plugins := analyzer.DefaultPluginsConfig()
	plugins.Plugins.LoopDetection.Threshold = 3
	plugins.Plugins.LoopDetection.WindowSeconds = 0

	dets := []analyzer.Detector{
		detectors.NewLoopDetector(3, 0),
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	az, err := analyzer.New(cfg, plugins, dets, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Write a repeating loop pattern: [search, write] × 3 = 6 events.
	base := time.Now()
	var events []*types.Event
	for rep := 0; rep < 3; rep++ {
		for i, name := range []string{"search", "write"} {
			events = append(events, makeToolEvent(
				fmt.Sprintf("e-%d-%d", rep, i),
				"sess-e2e",
				name,
				base.Add(time.Duration(rep*2+i)*time.Second),
			))
		}
	}

	writeEventFile(t, filepath.Join(eventsDir, "events-test.jsonl"), events)

	if err := az.Poll(context.Background()); err != nil {
		t.Fatalf("poll error: %v", err)
	}

	findings := readFindings(t, findingsDir)
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding, got 0")
	}

	found := false
	for _, f := range findings {
		if f.Type == string(types.DetectionLoop) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a task_loop finding, got: %+v", findings)
	}
}

// TestAnalyzer_CursorResumeFromOffset: second poll reads only new events.
func TestAnalyzer_CursorResumeFromOffset(t *testing.T) {
	eventsDir := t.TempDir()
	findingsDir := t.TempDir()

	cfg := newTestConfig(eventsDir, findingsDir)
	plugins := analyzer.DefaultPluginsConfig()
	plugins.Plugins.LoopDetection.Threshold = 3
	plugins.Plugins.LoopDetection.WindowSeconds = 0

	dets := []analyzer.Detector{
		detectors.NewLoopDetector(3, 0),
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	az, err := analyzer.New(cfg, plugins, dets, logger)
	if err != nil {
		t.Fatal(err)
	}

	eventsFile := filepath.Join(eventsDir, "events-resume.jsonl")
	base := time.Now()

	// First batch: 2 repetitions — below threshold → no findings.
	var batch1 []*types.Event
	for rep := 0; rep < 2; rep++ {
		for i, name := range []string{"ping", "pong"} {
			batch1 = append(batch1, makeToolEvent(
				fmt.Sprintf("b1-%d-%d", rep, i),
				"sess-resume",
				name,
				base.Add(time.Duration(rep*2+i)*time.Second),
			))
		}
	}
	writeEventFile(t, eventsFile, batch1)

	if err = az.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	findingsAfterBatch1 := readFindings(t, findingsDir)
	if len(findingsAfterBatch1) != 0 {
		t.Errorf("expected no findings after batch 1 (only 2 reps), got %d", len(findingsAfterBatch1))
	}

	// Second batch: append a 3rd repetition → triggers loop detection.
	f, err := os.OpenFile(eventsFile, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for i, name := range []string{"ping", "pong"} {
		e := makeToolEvent(
			fmt.Sprintf("b2-0-%d", i),
			"sess-resume",
			name,
			base.Add(time.Duration(4+i)*time.Second),
		)
		if err := enc.Encode(e); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	_ = f.Close()

	if err := az.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	findingsAfterBatch2 := readFindings(t, findingsDir)
	if len(findingsAfterBatch2) == 0 {
		t.Fatal("expected loop finding after 3rd repetition, got 0")
	}
}
