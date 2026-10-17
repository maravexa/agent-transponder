package eventstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/types"
)

func TestStoreConfinement(t *testing.T) {
	for _, tenant := range []string{"../outside", "/absolute", `a\b`, ".", "..", "a/../b"} {
		t.Run(tenant, func(t *testing.T) {
			s, err := NewJSONLStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.Append(context.Background(), &types.Event{TenantID: tenant}); err == nil {
				t.Fatal("unsafe tenant accepted")
			}
		})
	}
}

func TestStoreSymlinkConfinement(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	s, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = os.Symlink(out, filepath.Join(dir, "tenant")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(context.Background(), &types.Event{TenantID: "tenant", Timestamp: time.Now()}); err == nil {
		t.Fatal("directory symlink escaped")
	}
	outside := filepath.Join(out, "sentinel.jsonl")
	if err = os.WriteFile(outside, []byte("{}\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(dir, "outside.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Query(context.Background(), QueryFilter{}); err == nil {
		t.Fatal("read escaped root")
	}
}

func TestStorePinnedDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "events")
	s, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	moved := filepath.Join(parent, "moved")
	if err = os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err = s.Append(context.Background(), &types.Event{ID: "event", TenantID: "Acme Corp", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	events, err := s.Query(context.Background(), QueryFilter{})
	if err != nil || len(events) != 1 || events[0].TenantID != "Acme Corp" {
		t.Fatal(events, err)
	}
	info, err := os.Stat(filepath.Join(moved, "Acme Corp", now.UTC().Format("2006-01-02")+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("permissions changed: %v", info.Mode())
	}
}

func TestStoreLeafSymlinkWrite(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	s, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = os.Mkdir(filepath.Join(dir, "tenant"), 0750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(out, "sentinel")
	if err = os.WriteFile(outside, []byte("unchanged"), 0640); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	path := filepath.Join(dir, "tenant", now.UTC().Format("2006-01-02")+".jsonl")
	if err = os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(context.Background(), &types.Event{TenantID: "tenant", Timestamp: now}); err == nil {
		t.Fatal("leaf write escaped")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "unchanged" {
		t.Fatal("outside modified", err)
	}
}

// These allowed aliases document the threat-model limit, not an authorization
// promise: an operator-writable root can alias other tenants or hardlink data.
func TestStoreAllowsInRootSymlinkAndHardlink(t *testing.T) {
	for _, hard := range []bool{false, true} {
		t.Run(fmt.Sprint("hardlink=", hard), func(t *testing.T) { testStoreAlias(t, hard) })
	}
}

func testStoreAlias(t *testing.T, hard bool) {
	t.Helper()
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "other")
	if hard {
		targetDir = t.TempDir()
	}
	if err := os.MkdirAll(targetDir, 0750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetDir, "target")
	if err := os.WriteFile(target, nil, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "tenant"), 0750); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := filepath.Join(dir, "tenant", now.UTC().Format("2006-01-02")+".jsonl")
	var err error
	if hard {
		err = os.Link(target, leaf)
	} else {
		err = os.Symlink("../other/target", leaf)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(context.Background(), &types.Event{TenantID: "tenant", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil || len(data) == 0 {
		t.Fatalf("alias not followed: %q, %v", data, err)
	}
}
