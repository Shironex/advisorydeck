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
