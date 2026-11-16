package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/advisorydeck/image/internal/config"
	"github.com/Shironex/advisorydeck/image/internal/matching"
	"github.com/Shironex/advisorydeck/image/internal/notify"
	"github.com/Shironex/advisorydeck/image/internal/poll"
	"github.com/Shironex/advisorydeck/image/internal/state"
	"github.com/Shironex/advisorydeck/image/internal/testfeed"
)

type rig struct {
	t     *testing.T
	feed  *testfeed.Feed
	hook  *testfeed.Hook
	dir   string
	now   time.Time
	logs  *bytes.Buffer
	cfg   *config.Config
	hookN int
}

func newRig(t *testing.T, mode, minSeverity string) *rig {
	r := &rig{t: t, feed: testfeed.NewFeed(t), hook: testfeed.NewHook(t), dir: t.TempDir(), logs: &bytes.Buffer{},
		now: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	yml := fmt.Sprintf(`version: 1
feed:
  url: %s
products:
  - slug: postgresql
    version: '17'
min_severity: %s
mode: %s
digest:
  time: '08:00'
  timezone: Europe/Berlin
channels:
  - type: discord
    url_env: DISCORD_WEBHOOK_URL
    name: ops
state_path: %s
`, r.feed.Base(), minSeverity, mode, filepath.ToSlash(filepath.Join(r.dir, "state.json")))
	cfg, err := config.Parse([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	r.cfg = cfg
	return r
}

// engine builds a fresh engine on the same state file, like a container restart.
func (r *rig) engine(dry bool, out io.Writer) *Engine {
	log := slog.New(slog.NewJSONHandler(r.logs, nil))
	client := r.feed.Server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(r.hook.Server.Certificate())
	e := &Engine{
		Cfg:     r.cfg,
		Poll:    &poll.Client{HTTP: client, Base: r.cfg.Feed.URL, Log: log},
		Matcher: matching.Library{},
		Sender:  &notify.Sender{HTTP: client, Log: log, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
		Targets: []notify.Target{{ID: "discord:DISCORD_WEBHOOK_URL:ops", Type: "discord", Name: "ops", URLEnv: "DISCORD_WEBHOOK_URL", URL: r.hook.URL()}},
		Log:     log,
		DryRun:  dry,
		Out:     out,
		Now:     func() time.Time { return r.now },
	}
	if !dry {
		st, err := state.Open(r.cfg.StatePath)
		if err != nil {
			r.t.Fatal(err)
		}
		e.Store = st
		e.Poll.CacheDir = filepath.Join(r.dir, "feeds")
	}
	return e
}

func (r *rig) cycle(force bool) {
	r.t.Helper()
	if err := r.engine(false, nil).Cycle(context.Background(), force); err != nil {
		r.t.Fatal(err)
	}
}

// start gives the channel its first-start summary on a feed without advisories, then
// publishes the fixture advisories as if they appeared after the start.
func (r *rig) start() {
	r.t.Helper()
	var saved any
	r.feed.EditProduct(r.t, "postgresql", func(p map[string]any) {
		saved = p["advisories"]
		p["advisories"] = []any{}
	})
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		r.t.Fatalf("first start sent %d messages, want the summary", n)
	}
	r.feed.EditProduct(r.t, "postgresql", func(p map[string]any) { p["advisories"] = saved })
}

// newSends returns the number of webhook requests since the last call.
func (r *rig) newSends() int {
	n := len(r.hook.Bodies())
	d := n - r.hookN
	r.hookN = n
	return d
}

func TestInstantSendsOnceAcrossRestarts(t *testing.T) {
	r := newRig(t, "instant", "medium")
	r.start()
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("first cycle sent %d, want 1", n)
	}
	if !strings.Contains(string(r.hook.Bodies()[1]), "CVE-2026-120154") {
		t.Fatal("payload does not name the advisory")
	}
	r.cycle(false) // new engine on the same state: a restart
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("restarts resent %d messages", n)
	}
	if r.feed.NotModified() < 2 {
		t.Fatalf("manifest 304s = %d, If-None-Match not used", r.feed.NotModified())
	}
	// Two published versions of the file (empty at start, then with the advisory).
	if r.feed.Requests("products/postgresql.json") != 2 {
		t.Fatalf("product fetched %d times, want 2 (cached)", r.feed.Requests("products/postgresql.json"))
	}

	// A material change publishes a new revision: notify again, once.
	r.feed.EditProduct(t, "postgresql", func(p map[string]any) {
		p["advisories"].([]any)[0].(map[string]any)["revision"] = "sha256:" + strings.Repeat("1", 64)
	})
	r.cycle(false)
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("new revision sent %d, want 1", n)
	}
}

func TestSeverityFloor(t *testing.T) {
	r := newRig(t, "instant", "high")
	r.start()
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("medium advisory passed a high floor: %d", n)
	}
	// KEV bypasses the floor.
	r.feed.EditProduct(t, "postgresql", func(p map[string]any) {
		a := p["advisories"].([]any)[0].(map[string]any)
		a["kev"] = map[string]any{"listed": true, "added_at": "2026-11-15"}
		a["revision"] = "sha256:" + strings.Repeat("2", 64)
	})
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("KEV advisory sent %d, want 1", n)
	}
}

func TestDigestSchedule(t *testing.T) {
	r := newRig(t, "digest", "medium")
	r.start()
	r.cycle(false) // 12:00 UTC: the digest waits for the next 08:00 Berlin
	if n := r.newSends(); n != 0 {
		t.Fatalf("digest mode sent %d instantly", n)
	}
	r.now = time.Date(2026, 11, 17, 6, 59, 0, 0, time.UTC) // 07:59 in Berlin
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("digest sent early: %d", n)
	}
	r.now = time.Date(2026, 11, 17, 7, 1, 0, 0, time.UTC) // 08:01 in Berlin
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("digest sent %d messages, want 1", n)
	}
	if body := r.hook.Bodies()[len(r.hook.Bodies())-1]; !strings.Contains(string(body), "daily digest: 1 advisory") {
		t.Fatalf("not a digest: %s", body)
	}
	r.now = r.now.Add(25 * time.Hour)
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("same revision digested again: %d", n)
	}

	// KEV is instant even in digest mode.
	r.feed.EditProduct(t, "postgresql", func(p map[string]any) {
		a := p["advisories"].([]any)[0].(map[string]any)
		a["kev"] = map[string]any{"listed": true, "added_at": "2026-11-18"}
		a["revision"] = "sha256:" + strings.Repeat("3", 64)
	})
	r.now = r.now.Add(time.Hour)
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("KEV in digest mode sent %d, want 1 instantly", n)
	}
}

func TestActionRequiredIsInstant(t *testing.T) {
	r := newRig(t, "digest", "critical")
	r.start()
	r.feed.EditProduct(t, "postgresql", func(p map[string]any) {
		a := p["advisories"].([]any)[0].(map[string]any)
		a["note"].(map[string]any)["exposure"] = "default-exposed"
	})
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("action-required sent %d, want 1", n)
	}
}

func TestForceDigestAndBothMode(t *testing.T) {
	r := newRig(t, "both", "medium")
	r.start()
	r.cycle(true)
	if n := r.newSends(); n != 2 {
		t.Fatalf("both mode with a forced digest sent %d, want instant + digest", n)
	}
	r.cycle(true)
	if n := r.newSends(); n != 0 {
		t.Fatalf("resent %d", n)
	}
}

func TestDisabledWebhook(t *testing.T) {
	r := newRig(t, "instant", "medium")
	r.hook.Respond = func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }
	r.cycle(false)
	r.cycle(false)
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("dead webhook got %d requests, want 1", n)
	}
	st, err := state.Read(r.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if d := st.Channels["discord:DISCORD_WEBHOOK_URL:ops"].Disabled; d == nil || d.Status != 404 {
		t.Fatalf("disabled = %+v", d)
	}
	raw, _ := os.ReadFile(r.cfg.StatePath)
	if strings.Contains(string(raw), "fake-token") || strings.Contains(r.logs.String(), "fake-token") {
		t.Fatal("webhook URL leaked into state or logs")
	}

	// A new URL in the environment re-enables the channel.
	r.hook.Respond = nil
	e := r.engine(false, nil)
	e.Targets[0].URL = r.hook.URL() + "-new"
	if err := e.Cycle(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if n := r.newSends(); n != 1 {
		t.Fatalf("re-enabled channel sent %d, want 1", n)
	}
}

// The dry run says in words when nothing is open or the open advisory has no fix (issue #9).
func TestDryRunSummaryWithoutFix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ranges []any
		want   string
	}{
		{"nothing open", []any{map[string]any{"introduced": "18", "fixed": "18.7"}}, "postgresql 17: nothing open"},
		{"no fix", []any{}, "postgresql 17: 1 advisory open, no fix listed, check the vendor advisory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, "digest", "medium")
			r.feed.EditProduct(t, "postgresql", func(p map[string]any) {
				a := p["advisories"].([]any)[0].(map[string]any)
				a["affected"].([]any)[0].(map[string]any)["ranges"] = tc.ranges
			})
			var out bytes.Buffer
			if err := r.engine(true, &out).Cycle(context.Background(), false); err != nil {
				t.Fatal(err)
			}
			if s := out.String(); !strings.Contains(s, tc.want) || strings.Contains(s, `""`) {
				t.Errorf("dry run output lacks %q or shows an empty fix:\n%s", tc.want, s)
			}
		})
	}
}

func TestTransientFailureRetriesNextCycle(t *testing.T) {
	r := newRig(t, "instant", "medium")
	r.start()
	r.hook.Respond = func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }
	r.cycle(false)
	if n := r.newSends(); n != 6 {
		t.Fatalf("%d attempts, want 6", n)
	}
	r.hook.Respond = nil
	r.cycle(false)
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("after recovery sent %d, want 1", n)
	}
}

func TestDryRun(t *testing.T) {
	r := newRig(t, "digest", "medium")
	var out bytes.Buffer
	if err := r.engine(true, &out).Cycle(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if n := r.newSends(); n != 0 {
		t.Fatalf("dry run sent %d", n)
	}
	if _, err := os.Stat(r.cfg.StatePath); !os.IsNotExist(err) {
		t.Fatal("dry run wrote state")
	}
	s := out.String()
	for _, want := range []string{"dry run", "channel discord:DISCORD_WEBHOOK_URL:ops", "first start: 1 summary", `postgresql 17: 1 advisory open, run 17.12 or later`, "instant: 0", "digest: 0"} {
		if !strings.Contains(s, want) {
			t.Errorf("dry run output lacks %q:\n%s", want, s)
		}
	}

	// With the replay flag, the backlog follows the summary.
	out.Reset()
	e := r.engine(true, &out)
	e.ReplayBacklog = true
	if err := e.Cycle(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"the backlog follows", "digest: 1", "postgresql|fix:17.12: 1 advisories", "CVE-2026-120154", "branch 17 is affected before 17.12"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("replay dry run output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestFeedDown(t *testing.T) {
	r := newRig(t, "instant", "medium")
	r.feed.Server.Close()
	if err := r.engine(false, nil).Cycle(context.Background(), false); err == nil {
		t.Fatal("no error with the feed down")
	}
}

func TestDigestSlots(t *testing.T) {
	berlin, _ := time.LoadLocation("Europe/Berlin")
	now := time.Date(2026, 11, 16, 7, 30, 0, 0, time.UTC) // 08:30 Berlin
	if got := digestSlot(now, "08:00", berlin); !got.Equal(time.Date(2026, 11, 16, 8, 0, 0, 0, berlin)) {
		t.Errorf("slot = %v", got)
	}
	if got := nextDigestSlot(now, "08:00", berlin); !got.Equal(time.Date(2026, 11, 17, 8, 0, 0, 0, berlin)) {
		t.Errorf("next = %v", got)
	}
	if got := digestSlot(now, "09:00", berlin); !got.Equal(time.Date(2026, 11, 15, 9, 0, 0, 0, berlin)) {
		t.Errorf("earlier slot = %v", got)
	}
}

func TestRules(t *testing.T) {
	cases := []struct {
		level, min string
		want       bool
	}{
		{"critical", "high", true}, {"high", "high", true}, {"medium", "high", false},
		{"unknown", "low", false}, {"brand-new-level", "low", false}, {"low", "low", true},
	}
	for _, c := range cases {
		if got := passesFloor(c.level, c.min); got != c.want {
			t.Errorf("%s >= %s: %v", c.level, c.min, got)
		}
	}
}
