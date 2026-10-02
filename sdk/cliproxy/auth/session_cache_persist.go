package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// SessionAffinitySnapshotFileName is the file name used under the auth directory
// when routing.session-affinity-persist is enabled.
const SessionAffinitySnapshotFileName = "session-affinity.json"

const (
	sessionSnapshotVersion         = 1
	defaultSessionPersistInterval  = 30 * time.Second
	sessionSnapshotTempFileSuffix  = ".tmp"
	sessionSnapshotFilePermissions = 0o600
)

// SessionSnapshotEntry is one persisted alias group.
type SessionSnapshotEntry struct {
	Keys       []string  `json:"keys"`
	AuthID     string    `json:"auth_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	HomeAuthID string    `json:"home_auth_id,omitempty"`
	LastUsed   time.Time `json:"last_used,omitempty"`
}

// SessionSnapshot is the on-disk representation of the session cache.
type SessionSnapshot struct {
	Version int                    `json:"version"`
	SavedAt time.Time              `json:"saved_at"`
	Entries []SessionSnapshotEntry `json:"entries"`
}

// Snapshot returns all unexpired alias groups.
func (c *SessionCache) Snapshot() SessionSnapshot {
	snapshot := SessionSnapshot{Version: sessionSnapshotVersion}
	if c == nil {
		return snapshot
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.clock()
	snapshot.SavedAt = now
	snapshot.Entries = make([]SessionSnapshotEntry, 0, len(c.groups))
	for _, group := range c.groups {
		if !now.Before(group.expiresAt) {
			continue
		}
		snapshot.Entries = append(snapshot.Entries, SessionSnapshotEntry{
			Keys:       append([]string(nil), group.aliases...),
			AuthID:     group.authID,
			ExpiresAt:  group.expiresAt,
			HomeAuthID: group.homeAuthID,
			LastUsed:   group.lastUsed,
		})
	}
	return snapshot
}

// Restore merges unexpired snapshot entries into the cache, keeping their
// original expiry. Entries already present in the cache are replaced.
func (c *SessionCache) Restore(snapshot SessionSnapshot) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	now := c.clock()
	restored := 0
	for _, item := range snapshot.Entries {
		aliases := compactSessionAliases(mergeSessionAliases(nil, item.Keys...))
		if len(aliases) == 0 || item.AuthID == "" || !now.Before(item.ExpiresAt) {
			continue
		}
		previous := make([]sessionEntry, 0, len(aliases))
		for _, alias := range aliases {
			if existing, ok := c.entries[alias]; ok {
				previous = append(previous, existing)
			}
		}
		c.replaceAliasGroupsLocked(sessionEntry{
			authID:     item.AuthID,
			expiresAt:  item.ExpiresAt,
			aliases:    aliases,
			homeAuthID: item.HomeAuthID,
			lastUsed:   item.LastUsed,
		}, previous...)
		restored++
	}
	return restored
}

// SaveFile writes a snapshot atomically (temp file + rename) and clears the dirty flag.
func (c *SessionCache) SaveFile(path string) error {
	if c == nil || path == "" {
		return nil
	}
	c.saveMu.Lock()
	defer c.saveMu.Unlock()

	c.mu.Lock()
	c.dirty = false
	c.mu.Unlock()

	data, err := json.Marshal(c.Snapshot())
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + sessionSnapshotTempFileSuffix
	if err = os.WriteFile(tmp, data, sessionSnapshotFilePermissions); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// LoadFile restores bindings from a snapshot file. A missing file is not an
// error; a corrupt file is reported and otherwise ignored.
func (c *SessionCache) LoadFile(path string) (int, error) {
	if c == nil || path == "" {
		return 0, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var snapshot SessionSnapshot
	if err = json.Unmarshal(data, &snapshot); err != nil {
		return 0, err
	}
	if snapshot.Version != sessionSnapshotVersion {
		return 0, errors.New("unsupported session affinity snapshot version")
	}
	restored := c.Restore(snapshot)
	c.mu.Lock()
	c.dirty = false
	c.mu.Unlock()
	return restored, nil
}

// EnablePersistence loads the snapshot at path and starts a loop that writes
// it back every interval while the cache is dirty, plus once on Stop.
func (c *SessionCache) EnablePersistence(path string, interval time.Duration) {
	if c == nil || path == "" {
		return
	}
	if interval <= 0 {
		interval = defaultSessionPersistInterval
	}
	if restored, err := c.LoadFile(path); err != nil {
		log.Warnf("session-affinity: ignoring snapshot %s: %v", path, err)
	} else if restored > 0 {
		log.Infof("session-affinity: restored %d session bindings from %s", restored, path)
	}
	c.mu.Lock()
	c.persistPath = path
	c.mu.Unlock()
	go c.persistLoop(interval)
}

func (c *SessionCache) persistLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.persistIfDirty()
		}
	}
}

func (c *SessionCache) persistIfDirty() {
	c.mu.RLock()
	path, dirty := c.persistPath, c.dirty
	c.mu.RUnlock()
	if path == "" || !dirty {
		return
	}
	if err := c.SaveFile(path); err != nil {
		log.Warnf("session-affinity: failed to persist snapshot %s: %v", path, err)
	}
}
