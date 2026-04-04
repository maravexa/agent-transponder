package analyzer_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/analyzer"
)

func TestCursor_WriteReadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cursor.json")

	c := analyzer.NewCursor()
	c.Set("events-2025-01-01.jsonl", analyzer.FileCursor{
		Offset:   4096,
		LastRead: time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC),
	})

	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	c2, err := analyzer.LoadCursor(path)
	if err != nil {
		t.Fatalf("LoadCursor: %v", err)
	}

	fc := c2.Get("events-2025-01-01.jsonl")
	if fc.Offset != 4096 {
		t.Errorf("expected offset 4096, got %d", fc.Offset)
	}
	if !fc.LastRead.Equal(time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)) {
		t.Errorf("unexpected LastRead: %v", fc.LastRead)
	}
}

func TestCursor_MissingFileReturnsEmpty(t *testing.T) {
	c, err := analyzer.LoadCursor("/tmp/does-not-exist-cursor.json")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	fc := c.Get("nonexistent.jsonl")
	if fc.Offset != 0 {
		t.Errorf("expected zero offset for unseen file, got %d", fc.Offset)
	}
}

func TestCursor_AtomicSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cursor.json")

	c := analyzer.NewCursor()
	c.Set("a.jsonl", analyzer.FileCursor{Offset: 100})

	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}

	// Ensure no tmp file left behind.
	tmp := path + ".tmp"
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("expected tmp file to be cleaned up after save")
	}

	// Final file must exist.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("cursor file not written: %v", err)
	}
}

func TestCursorPath(t *testing.T) {
	p := analyzer.CursorPath("/var/lib/flight-recorder/findings")
	expected := "/var/lib/flight-recorder/findings/.cursor.json"
	if p != expected {
		t.Errorf("expected %s, got %s", expected, p)
	}
}
