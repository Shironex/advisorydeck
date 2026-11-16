// Package state keeps what the daemon already sent, per channel, in one small JSON file
// on the data volume, so a restart never sends the same advisory revision twice.
//
// The file is replaced atomically (write to a temporary file in the same folder, fsync,
// rename), so a crash or a concurrent healthcheck never sees half a file.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Version is the state file format version. Version 1 files (written before release
// bundles and the first-start summary) are migrated on open: see migrate.
const Version = 2

// File is the on-disk shape.
type File struct {
	Version int `json:"version"`
	// ManifestETag is the HTTP ETag of the last manifest response, for If-None-Match.
	ManifestETag string `json:"manifest_etag,omitempty"`
	// LastPollOK is when the feed was last read successfully (the healthcheck reads it).
	LastPollOK time.Time `json:"last_poll_ok,omitempty"`
	// Channels is keyed by channel id (type:url_env:name).
	Channels map[string]*Channel `json:"channels"`
}

// Channel is what one webhook already received.
type Channel struct {
	// Instant maps an item key (advisory id|product) to the revision sent instantly.
	Instant map[string]string `json:"instant"`
	// Digest maps an item key to the revision included in a sent digest.
	Digest map[string]string `json:"digest"`
	// LastDigest is when the last digest slot was handled (sent or empty).
	LastDigest time.Time `json:"last_digest,omitempty"`
	// Started is when the channel got its first-start summary. Zero means it has not: the
	// next cycle sends the summary instead of the backlog.
	Started time.Time `json:"started,omitempty"`
	// Disabled is set when the webhook answered 401/403/404/410.
	Disabled *Disabled `json:"disabled,omitempty"`
}

// Disabled records a permanently failing webhook. Fingerprint identifies the URL it
// failed with (a truncated hash, never the URL), so a new URL re-enables the channel.
type Disabled struct {
	Fingerprint string    `json:"fingerprint"`
	Status      int       `json:"status"`
	At          time.Time `json:"at"`
}

// Store is the in-memory state guarded by a mutex, saved on demand.
type Store struct {
	mu   sync.Mutex
	path string
	data File
}

// Open reads the state file, or starts empty when it does not exist yet.
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: File{Version: Version, Channels: map[string]*Channel{}}}
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("state %s: %w", path, err)
	}
	if s.data.Channels == nil {
		s.data.Channels = map[string]*Channel{}
	}
	if s.data.Version == 1 {
		migrate(&s.data, time.Now())
	}
	if s.data.Version != Version {
		return nil, fmt.Errorf("state %s: version %d, want %d (written by a newer image?)", path, s.data.Version, Version)
	}
	return s, nil
}

// migrate moves a version 1 file forward without resending anything. Every channel in it
// already received its backlog one advisory at a time, so it counts as started: it gets no
// summary. The sent revisions keep their keys (advisory id|product), which is what bundles
// are checked against, so nothing already sent is pending. The file is written on the next
// save.
func migrate(f *File, now time.Time) {
	for _, c := range f.Channels {
		if c == nil || !c.Started.IsZero() {
			continue
		}
		c.Started = now
		if !c.LastDigest.IsZero() {
			c.Started = c.LastDigest
		}
	}
	f.Version = Version
}

// Read loads the state file without creating a Store, for the healthcheck.
func Read(path string) (*File, error) {
	s, err := Open(path)
	if err != nil {
		return nil, err
	}
	return &s.data, nil
}

// Path returns the state file path.
func (s *Store) Path() string { return s.path }

// Update runs fn with the state locked. Changes are kept in memory until Save.
func (s *Store) Update(fn func(f *File)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
}

// View runs fn with the state locked, for reads.
func (s *Store) View(fn func(f *File)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
}

// Channel returns the record of one channel, creating it when missing. Call it inside
// Update or View.
func (f *File) Channel(id string) *Channel {
	c := f.Channels[id]
	if c == nil {
		c = &Channel{}
		f.Channels[id] = c
	}
	if c.Instant == nil {
		c.Instant = map[string]string{}
	}
	if c.Digest == nil {
		c.Digest = map[string]string{}
	}
	return c
}

// Save writes the state atomically.
func (s *Store) Save() error {
	s.mu.Lock()
	raw, err := json.MarshalIndent(&s.data, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path, append(raw, '\n'))
}

// WriteFileAtomic replaces path with data via a temporary file in the same folder.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, path)
}
