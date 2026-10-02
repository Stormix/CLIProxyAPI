package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionCachePersistRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "session-affinity.json")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	source := NewSessionCache(time.Hour)
	defer source.Stop()
	source.now = func() time.Time { return base }
	source.SetAliases("auth-1", "p::s1::m", "p::pck:1::m")
	source.Set("p::s2::m", "auth-2")
	source.SetHome("p::s2::m", "auth-home")
	if err := source.SaveFile(path); err != nil {
		t.Fatalf("SaveFile() error = %v", err)
	}
	if _, err := os.Stat(path + sessionSnapshotTempFileSuffix); !os.IsNotExist(err) {
		t.Fatalf("temp file should be renamed away, stat err = %v", err)
	}

	// Load 30 minutes later: both entries (1h TTL) are still valid.
	target := NewSessionCache(time.Hour)
	defer target.Stop()
	target.now = func() time.Time { return base.Add(30 * time.Minute) }
	restored, err := target.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if restored != 2 {
		t.Fatalf("restored = %d, want 2", restored)
	}
	for _, key := range []string{"p::s1::m", "p::pck:1::m"} {
		if got, ok := target.Get(key); !ok || got != "auth-1" {
			t.Fatalf("Get(%q) = %q, %v; want auth-1", key, got, ok)
		}
	}
	binding, ok := target.Binding("p::s2::m")
	if !ok || binding.AuthID != "auth-2" || binding.HomeAuthID != "auth-home" || !binding.LastUsed.Equal(base) {
		t.Fatalf("Binding(p::s2::m) = %+v, %v; want auth-2/auth-home/%s", binding, ok, base)
	}

	// Load after the TTL: everything is expired and dropped.
	expired := NewSessionCache(time.Hour)
	defer expired.Stop()
	expired.now = func() time.Time { return base.Add(2 * time.Hour) }
	restored, err = expired.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() after expiry error = %v", err)
	}
	if restored != 0 || expired.Len() != 0 {
		t.Fatalf("expired snapshot restored %d entries (len %d), want 0", restored, expired.Len())
	}
}

func TestSessionCachePersistIgnoresMissingAndCorruptFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache := NewSessionCache(time.Hour)
	defer cache.Stop()

	if restored, err := cache.LoadFile(filepath.Join(dir, "missing.json")); err != nil || restored != 0 {
		t.Fatalf("LoadFile(missing) = %d, %v; want 0, nil", restored, err)
	}

	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.LoadFile(corrupt); err == nil {
		t.Fatal("LoadFile(corrupt) expected an error")
	}
	if cache.Len() != 0 {
		t.Fatalf("corrupt file populated cache: len = %d", cache.Len())
	}

	// EnablePersistence must tolerate the corrupt file and keep the cache usable.
	cache.EnablePersistence(corrupt, time.Hour)
	cache.Set("k", "auth")
	if got, ok := cache.Get("k"); !ok || got != "auth" {
		t.Fatalf("cache unusable after corrupt snapshot: %q, %v", got, ok)
	}
}

func TestSessionCacheStopFlushesWhenDirty(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "session-affinity.json")
	cache := NewSessionCache(time.Hour)
	cache.EnablePersistence(path, time.Hour)
	cache.Set("p::s::m", "auth-1")
	cache.Stop()

	reloaded := NewSessionCache(time.Hour)
	defer reloaded.Stop()
	if restored, err := reloaded.LoadFile(path); err != nil || restored != 1 {
		t.Fatalf("LoadFile() after Stop = %d, %v; want 1, nil", restored, err)
	}
	if got, ok := reloaded.Get("p::s::m"); !ok || got != "auth-1" {
		t.Fatalf("Get() = %q, %v; want auth-1", got, ok)
	}
}
