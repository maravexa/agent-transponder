package analyzer

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAnalyzerConfinement(t *testing.T) {
	events, findings, out := t.TempDir(), t.TempDir(), t.TempDir()
	a, err := New(&Config{Events: EventsConfig{Path: events}, Findings: FindingsConfig{Path: findings}}, DefaultPluginsConfig(), nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	sentinel := filepath.Join(out, "outside.jsonl")
	original := []byte("{\"id\":\"outside\"}\n")
	if err = os.WriteFile(sentinel, original, 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(sentinel, filepath.Join(events, "escape.jsonl")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"escape.jsonl", "../outside.jsonl", sentinel} {
		if _, _, err = a.readNewEvents(path, 0); err == nil {
			t.Fatalf("read escaped: %s", path)
		}
	}
	name := "findings-" + time.Now().UTC().Format("2006-01-02") + ".jsonl"
	if err = os.Symlink(sentinel, filepath.Join(findings, name)); err != nil {
		t.Fatal(err)
	}
	if err = a.writeFindings([]Finding{{}}); err == nil {
		t.Fatal("findings write escaped")
	}
	if err = os.Symlink(sentinel, filepath.Join(findings, ".cursor.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = loadCursor(a.findingsRoot, ".cursor.json"); err == nil {
		t.Fatal("cursor read escaped")
	}
	if err = a.cursor.save(a.findingsRoot, ".cursor.json"); err != nil {
		t.Fatal(err)
	} // replaces link, never follows it
	got, err := os.ReadFile(sentinel)
	if err != nil || string(got) != string(original) {
		t.Fatal("outside modified", err)
	}
	if err = a.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCursorTenantIsolation(t *testing.T) {
	events, findings := t.TempDir(), t.TempDir()
	for _, tenant := range []string{"one", "two"} {
		dir := filepath.Join(events, tenant)
		if err := os.Mkdir(dir, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "2026-10-17.jsonl"), []byte("{\"id\":\""+tenant+"\"}\n"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	a, err := New(&Config{Events: EventsConfig{Path: events}, Findings: FindingsConfig{Path: findings}}, DefaultPluginsConfig(), nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err = a.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(a.cursor.Files) != 2 {
		t.Fatalf("tenant cursor collision: %+v", a.cursor.Files)
	}
}

// Basename offsets cannot safely be assigned to either nested tenant. Preserve
// root-level offsets, replay each nested file, and persist distinct new keys.
func TestLegacyCursorReplay(t *testing.T) {
	events, findings := t.TempDir(), t.TempDir()
	name := "2026-10-17.jsonl"
	data := []byte("{\"id\":\"fixture\"}\n")
	for _, dir := range []string{".", "one", "two"} {
		if err := os.MkdirAll(filepath.Join(events, dir), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(events, dir, name), data, 0640); err != nil {
			t.Fatal(err)
		}
	}
	cursor := NewCursor()
	cursor.Set(name, FileCursor{Offset: int64(len(data))})
	if err := cursor.Save(CursorPath(findings)); err != nil {
		t.Fatal(err)
	}
	a, err := New(&Config{Events: EventsConfig{Path: events}, Findings: FindingsConfig{Path: findings}}, DefaultPluginsConfig(), nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for _, dir := range []string{"one", "two"} {
		if a.cursor.Get(dir+"/"+name).Offset != 0 {
			t.Fatal("legacy offset reused")
		}
	}
	if err = a.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved, err := LoadCursor(CursorPath(findings))
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Files) != 3 {
		t.Fatalf("keys: %+v", saved.Files)
	}
	for _, path := range []string{name, "one/" + name, "two/" + name} {
		if saved.Get(path).Offset != int64(len(data)) {
			t.Fatalf("offset %s: %+v", path, saved.Get(path))
		}
	}
	if err = a.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
}
