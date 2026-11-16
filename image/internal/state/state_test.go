package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	s.Update(func(f *File) {
		f.ManifestETag = `"abc"`
		f.LastPollOK = now
		c := f.Channel("discord:DISCORD_WEBHOOK_URL:ops")
		c.Instant["CVE-1|postgresql"] = "sha256:1"
		c.Disabled = &Disabled{Fingerprint: "ff", Status: 404, At: now}
	})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	again.View(func(f *File) {
		c := f.Channel("discord:DISCORD_WEBHOOK_URL:ops")
		if f.ManifestETag != `"abc"` || !f.LastPollOK.Equal(now) || c.Instant["CVE-1|postgresql"] != "sha256:1" || c.Disabled.Status != 404 {
			t.Fatalf("state = %+v / %+v", f, c)
		}
	})
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("leftover temp files: %v", entries)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
}

func TestOpenMissingAndBroken(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(filepath.Join(dir, "none.json")); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(broken); err == nil {
		t.Fatal("broken file accepted")
	}
	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(future); err == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestMigratesVersion1WithoutResending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	v1 := `{
  "version": 1,
  "manifest_etag": "\"abc\"",
  "channels": {
    "discord:DISCORD_WEBHOOK_URL:ops": {
      "instant": {"CVE-2026-120154|postgresql": "sha256:aa"},
      "digest": {},
      "last_digest": "2026-11-15T07:00:00Z"
    }
  }
}`
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	c := f.Channels["discord:DISCORD_WEBHOOK_URL:ops"]
	if f.Version != Version || c.Started.IsZero() || c.Instant["CVE-2026-120154|postgresql"] != "sha256:aa" || f.ManifestETag != `"abc"` {
		t.Fatalf("migrated = %+v, channel %+v", f, c)
	}
	if !c.Started.Equal(time.Date(2026, 11, 15, 7, 0, 0, 0, time.UTC)) {
		t.Errorf("started = %v, want the last digest time", c.Started)
	}
	if err := os.WriteFile(path, []byte(`{"version":3,"channels":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Error("a newer state version was accepted")
	}
}
