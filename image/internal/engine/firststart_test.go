package engine

import (
	"context"
	"encoding/json"
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
	"github.com/Shironex/advisorydeck/image/internal/contracttest"
	"github.com/Shironex/advisorydeck/image/internal/matching"
	"github.com/Shironex/advisorydeck/image/internal/notify"
	"github.com/Shironex/advisorydeck/image/internal/poll"
	"github.com/Shironex/advisorydeck/image/internal/state"
	"github.com/Shironex/advisorydeck/image/internal/testfeed"
)

// committedFeed serves the whole committed feed in data/api/v1.
func committedFeed(t *testing.T) *testfeed.Feed {
	t.Helper()
	f := testfeed.NewFeed(t)
	for slug, rp := range loadReplayData(t) {
		raw, err := json.Marshal(rp.raw)
		if err != nil {
			t.Fatal(err)
		}
		f.SetProduct(t, slug, raw)
	}
	return f
}

// exampleConfig is fixtures/image/advisorydeck.yml pointed at a test feed and state folder,
// with its products, severity floor and channels unchanged.
func exampleConfig(t *testing.T, feedURL, mode, statePath string) *config.Config {
	t.Helper()
	raw, err := os.ReadFile(contracttest.Path(t, "fixtures/image/advisorydeck.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yml := strings.Replace(string(raw), "https://feed.example.org/api/v1/", feedURL, 1)
	yml = strings.Replace(yml, "mode: digest", "mode: "+mode, 1)
	yml = strings.Replace(yml, "state_path: /data/state.json", "state_path: "+filepath.ToSlash(statePath), 1)
	cfg, err := config.Parse([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

type firstStart struct {
	sent map[string][][]byte // per channel type
}

func runFirstStart(t *testing.T, mode string, replay bool, statePath string) firstStart {
	t.Helper()
	f := committedFeed(t)
	discord, generic := testfeed.NewHook(t), testfeed.NewHook(t)
	cfg := exampleConfig(t, f.Base(), mode, statePath)
	client := f.Server.Client()
	pool := client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	pool.AddCert(discord.Server.Certificate())
	pool.AddCert(generic.Server.Certificate())
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	st, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		Cfg:     cfg,
		Poll:    &poll.Client{HTTP: client, Base: cfg.Feed.URL, Log: log, CacheDir: filepath.Join(filepath.Dir(statePath), "feeds")},
		Matcher: matching.Library{},
		Sender:  &notify.Sender{HTTP: client, Log: log, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
		Targets: []notify.Target{
			{ID: "discord:DISCORD_WEBHOOK_URL:ops", Type: "discord", Name: "ops", URLEnv: "DISCORD_WEBHOOK_URL", URL: discord.URL()},
			{ID: "webhook:GENERIC_WEBHOOK_URL:", Type: "webhook", URLEnv: "GENERIC_WEBHOOK_URL", URL: generic.URL()},
		},
		Log:           log,
		Store:         st,
		ReplayBacklog: replay,
		Out:           io.Discard,
		Now:           func() time.Time { return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) },
	}
	if err := e.Cycle(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	return firstStart{sent: map[string][][]byte{"discord": discord.Bodies(), "webhook": generic.Bodies()}}
}

// The example config against the committed 12-month feed used to post 60 messages per
// channel on first start (issue #5). Now it posts one summary per channel.
func TestFirstStartOnCommittedFeed(t *testing.T) {
	for _, mode := range []string{"instant", "digest", "both"} {
		dir := t.TempDir()
		res := runFirstStart(t, mode, false, filepath.Join(dir, "state.json"))
		for ch, bodies := range res.sent {
			if len(bodies) != 1 {
				t.Fatalf("%s mode, %s: %d messages on first start, want 1 summary", mode, ch, len(bodies))
			}
		}
		var summary struct {
			Kind    string `json:"kind"`
			Summary struct {
				Products []struct {
					Product string   `json:"product"`
					Open    []string `json:"open"`
					Latest  string   `json:"latest"`
				} `json:"products"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(res.sent["webhook"][0], &summary); err != nil {
			t.Fatal(err)
		}
		if summary.Kind != "summary" || len(summary.Summary.Products) != 3 {
			t.Fatalf("summary = %+v", summary)
		}
		pg := summary.Summary.Products[0]
		if pg.Product != "postgresql" || pg.Latest != "17.12" || len(pg.Open) == 0 {
			t.Errorf("postgresql summary = %+v", pg)
		}
		if !strings.Contains(string(res.sent["discord"][0]), "Make sure you run 17.12 or later") {
			t.Errorf("discord summary lacks the one action: %s", res.sent["discord"][0])
		}

		// A restart on the same state sends nothing more.
		again := runFirstStart(t, mode, false, filepath.Join(dir, "state.json"))
		for ch, bodies := range again.sent {
			if len(bodies) != 0 {
				t.Fatalf("%s mode, %s: restart sent %d", mode, ch, len(bodies))
			}
		}
	}
}

// With -replay-backlog the backlog follows the summary, still collapsed: one message per
// product (several releases due at once are one group message), older releases of a
// floating branch covered by the newest one.
func TestFirstStartReplayOnCommittedFeed(t *testing.T) {
	res := runFirstStart(t, "instant", true, filepath.Join(t.TempDir(), "state.json"))
	for ch, bodies := range res.sent {
		if len(bodies) < 2 || len(bodies) > 4 {
			t.Errorf("%s: %d messages with the backlog replayed, want the summary plus at most one per product", ch, len(bodies))
		}
		t.Logf("%s: %d messages", ch, len(bodies))
	}
	for i, body := range res.sent["webhook"] {
		var p struct {
			Kind  string `json:"kind"`
			Items []struct {
				Product string `json:"product"`
				ID      string `json:"advisory_id"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		products := map[string]bool{}
		for _, it := range p.Items {
			products[it.Product] = true
		}
		t.Logf("message %d: %s, %d advisories, products %v", i, p.Kind, len(p.Items), keys(products))
	}
}

func keys(m map[string]bool) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return fmt.Sprint(out)
}
