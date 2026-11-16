package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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

// The replay measures message volume against the committed 12-month feed in data/: the
// image starts on the first day with an empty feed, and every advisory appears on the day
// it was published, with the ranges and revision it has today (the history of revisions is
// not kept, so revised advisories are not replayed). Two cycles a day, at 09:00 and 21:00
// UTC, a digest at 08:00 UTC.
//
// TestReplay asserts the targets; set ADVISORYDECK_REPLAY_REPORT=1 and run it with -v to
// print the table (go test ./internal/engine -run TestReplay -v).

type replayConfig struct {
	name     string
	products [][2]string
}

var replayConfigs = []replayConfig{
	{"example (fixtures/image/advisorydeck.yml)", [][2]string{{"postgresql", "17"}, {"traefik", "3.7.19"}, {"coolify", "4.0.0-beta.474"}}},
	{"pinned old versions", [][2]string{{"postgresql", "16.4"}, {"redis", "7.2.4"}, {"traefik", "3.1.2"}, {"docker-engine", "27.3.1"}, {"coolify", "4.0.0-beta.420"}}},
	{"floating branches", [][2]string{{"postgresql", "16"}, {"redis", "7.4"}, {"traefik", "3.6"}, {"docker-engine", "28"}}},
	{"recent exact versions", [][2]string{{"postgresql", "17.6"}, {"redis", "8.0.2"}, {"traefik", "3.5.0"}, {"docker-engine", "28.3.0"}, {"coolify", "4.0.0-beta.440"}}},
}

// replayResult counts the messages one config produced.
type replayResult struct {
	// perProduct counts instant messages per product per ISO week.
	perProduct map[string]map[string]int
	// digests counts digest messages per week; summaries counts first-start summaries.
	digests   map[string]int
	summaries int
	total     int
}

type replayAdvisory struct {
	PublishedAt time.Time `json:"published_at"`
}

type replayProduct struct {
	raw        map[string]any
	advisories []any
	published  []time.Time
}

func loadReplayData(t *testing.T) map[string]*replayProduct {
	t.Helper()
	dir := contracttest.Path(t, "data/api/v1/products")
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*replayProduct{}
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n.Name())) // #nosec G304 -- the committed feed in the repository
		if err != nil {
			t.Fatal(err)
		}
		var p map[string]any
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		var typed struct {
			Advisories []replayAdvisory `json:"advisories"`
		}
		if err := json.Unmarshal(raw, &typed); err != nil {
			t.Fatal(err)
		}
		rp := &replayProduct{raw: p, advisories: p["advisories"].([]any)}
		for _, a := range typed.Advisories {
			rp.published = append(rp.published, a.PublishedAt)
		}
		out[strings.TrimSuffix(n.Name(), ".json")] = rp
	}
	return out
}

func runReplay(t *testing.T, data map[string]*replayProduct, rc replayConfig, mode, minSeverity string) replayResult {
	t.Helper()
	f := testfeed.NewFeed(t)
	hook := testfeed.NewHook(t)
	dir := t.TempDir()
	var yml strings.Builder
	fmt.Fprintf(&yml, "version: 1\nfeed:\n  url: %s\nproducts:\n", f.Base())
	for _, p := range rc.products {
		fmt.Fprintf(&yml, "  - slug: %s\n    version: '%s'\n", p[0], p[1])
	}
	fmt.Fprintf(&yml, "min_severity: %s\nmode: %s\ndigest:\n  time: '08:00'\n  timezone: UTC\nchannels:\n  - type: webhook\n    url_env: HOOK\nstate_path: %s\n",
		minSeverity, mode, filepath.ToSlash(filepath.Join(dir, "state.json")))
	cfg, err := config.Parse([]byte(yml.String()))
	if err != nil {
		t.Fatal(err)
	}
	client := f.Server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(hook.Server.Certificate())
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	start := time.Date(2025, 11, 16, 9, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	res := replayResult{perProduct: map[string]map[string]int{}, digests: map[string]int{}}
	seen := 0
	for now := start; !now.After(end); now = now.Add(12 * time.Hour) {
		for _, p := range rc.products {
			rp := data[p[0]]
			if rp == nil {
				continue
			}
			var visible []any
			for i, a := range rp.advisories {
				if !rp.published[i].After(now) {
					visible = append(visible, a)
				}
			}
			if visible == nil {
				visible = []any{}
			}
			copyP := map[string]any{}
			for k, v := range rp.raw {
				copyP[k] = v
			}
			copyP["advisories"] = visible
			raw, err := json.Marshal(copyP)
			if err != nil {
				t.Fatal(err)
			}
			f.SetProduct(t, p[0], raw)
		}
		st, err := state.Open(cfg.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		at := now
		e := &Engine{
			Cfg:     cfg,
			Poll:    &poll.Client{HTTP: client, Base: cfg.Feed.URL, Log: log, CacheDir: filepath.Join(dir, "feeds")},
			Matcher: matching.Library{},
			Sender:  &notify.Sender{HTTP: client, Log: log, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
			Targets: []notify.Target{{ID: "webhook:HOOK:", Type: "webhook", URLEnv: "HOOK", URL: hook.URL()}},
			Log:     log,
			Store:   st,
			Out:     io.Discard,
			Now:     func() time.Time { return at },
		}
		if err := e.Cycle(context.Background(), false); err != nil {
			t.Fatal(err)
		}
		bodies := hook.Bodies()
		year, week := now.ISOWeek()
		wk := fmt.Sprintf("%d-W%02d", year, week)
		for _, body := range bodies[seen:] {
			var payload struct {
				Kind  string `json:"kind"`
				Items []struct {
					Product string `json:"product"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			res.total++
			switch {
			case payload.Kind == "summary":
				res.summaries++
			case payload.Kind == "digest":
				res.digests[wk]++
			case len(payload.Items) > 0:
				prod := payload.Items[0].Product
				if res.perProduct[prod] == nil {
					res.perProduct[prod] = map[string]int{}
				}
				res.perProduct[prod][wk]++
			}
		}
		seen = len(bodies)
	}
	return res
}

func maxAndSum(m map[string]int) (int, int) {
	most, sum := 0, 0
	for _, n := range m {
		sum += n
		if n > most {
			most = n
		}
	}
	return most, sum
}

func TestReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("replays a year of the committed feed")
	}
	data := loadReplayData(t)
	var report bytes.Buffer
	fmt.Fprintf(&report, "| Config | Mode | Product | Messages in 52 weeks | Weeks with a message | Most in one week | Per week |\n|---|---|---|---|---|---|---|\n")
	for _, rc := range replayConfigs {
		for _, mode := range []string{"instant", "digest"} {
			res := runReplay(t, data, rc, mode, "high")
			var slugs []string
			for _, p := range rc.products {
				slugs = append(slugs, p[0])
			}
			sort.Strings(slugs)
			for _, slug := range slugs {
				weeks := res.perProduct[slug]
				most, sum := maxAndSum(weeks)
				fmt.Fprintf(&report, "| %s | %s | %s | %d | %d | %d | %.2f |\n", rc.name, mode, slug, sum, len(weeks), most, float64(sum)/52)
				// The target: a handful a week per product at high, never a flood.
				if most > 3 {
					t.Errorf("%s, %s: %s posted %d messages in one week", rc.name, mode, slug, most)
				}
			}
			most, sum := maxAndSum(res.digests)
			fmt.Fprintf(&report, "| %s | %s | digests | %d | %d | %d | %.2f |\n", rc.name, mode, sum, len(res.digests), most, float64(sum)/52)
			fmt.Fprintf(&report, "| %s | %s | first-start summaries | %d | | | |\n", rc.name, mode, res.summaries)
		}
	}
	if os.Getenv("ADVISORYDECK_REPLAY_REPORT") != "" {
		t.Log("\n" + report.String())
	}
}
