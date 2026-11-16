package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
	"github.com/Shironex/advisorydeck/image/internal/feed"
	"github.com/Shironex/advisorydeck/image/internal/matching"
	"github.com/Shironex/advisorydeck/image/internal/testfeed"
)

func fixtureItem(t *testing.T) Item {
	t.Helper()
	raw, err := os.ReadFile(contracttest.Path(t, "fixtures/api/v1/products/postgresql.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := feed.DecodeProductFeed(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	a := p.Advisories[0]
	return Item{Key: Key(a.ID, "postgresql"), Advisory: a, Product: p.Product, Declared: "17", Verdict: matching.Affected, Reason: "branch 17 is affected before 17.12", FixedIn: "17.12"}
}

// hostile makes an item with oversized, mention-laden text.
func hostile(t *testing.T, i int) Item {
	it := fixtureItem(t)
	it.Advisory.ID = it.Advisory.ID + "-" + string(rune('a'+i%26))
	it.Advisory.Title = "@everyone " + strings.Repeat("T", 400)
	it.Advisory.Summary = "@here <!channel> " + strings.Repeat("S", 9000)
	n := *it.Advisory.Note
	n.Assumptions = []string{strings.Repeat("A", 300), strings.Repeat("B", 300), strings.Repeat("C", 300), strings.Repeat("D", 300)}
	n.Actions = []feed.Action{{Kind: "commands", Code: strings.Repeat("x", 2000)}}
	it.Advisory.Note = &n
	return it
}

func TestDiscordLimits(t *testing.T) {
	var items []Item
	for i := 0; i < 23; i++ {
		items = append(items, hostile(t, i))
	}
	for _, kind := range []Kind{Instant, Digest} {
		in := items
		if kind == Instant {
			in = items[:1]
		}
		msgs, err := Discord{}.Render(in, kind, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, m := range msgs {
			var dm discordMessage
			if err := json.Unmarshal(m.Payload, &dm); err != nil {
				t.Fatal(err)
			}
			if dm.AllowedMentions.Parse == nil || len(dm.AllowedMentions.Parse) != 0 || !strings.Contains(string(m.Payload), `"allowed_mentions":{"parse":[]}`) {
				t.Fatalf("allowed_mentions missing: %s", m.Payload[:200])
			}
			if len(dm.Embeds) == 0 || len(dm.Embeds) > discordEmbedsMax || len(dm.Embeds) != len(m.Items) {
				t.Fatalf("%d embeds for %d items", len(dm.Embeds), len(m.Items))
			}
			if utf8.RuneCountInString(dm.Content) > discordContentMax {
				t.Fatal("content too long")
			}
			total := 0
			for _, e := range dm.Embeds {
				total += e.size()
				if utf8.RuneCountInString(e.Title) > discordTitleMax || utf8.RuneCountInString(e.Description) > discordDescriptionMax || len(e.Fields) > discordFieldsMax {
					t.Fatalf("embed over limits: title %d desc %d fields %d", utf8.RuneCountInString(e.Title), utf8.RuneCountInString(e.Description), len(e.Fields))
				}
				for _, f := range e.Fields {
					if utf8.RuneCountInString(f.Name) > discordFieldNameMax || utf8.RuneCountInString(f.Value) > discordFieldValueMax {
						t.Fatalf("field %q over limits", f.Name)
					}
				}
				if strings.Contains(e.Title, "@everyone") || strings.Contains(e.Description, "@here") {
					t.Fatal("mention not defused")
				}
			}
			if total > discordTotalMax {
				t.Fatalf("message has %d characters", total)
			}
			count += len(m.Items)
		}
		if count != len(in) {
			t.Fatalf("%s: %d items rendered, want %d", kind, count, len(in))
		}
	}
}

func TestDiscordContent(t *testing.T) {
	msgs, err := Discord{}.Render([]Item{fixtureItem(t)}, Instant, time.Now())
	if err != nil || len(msgs) != 1 {
		t.Fatal(msgs, err)
	}
	s := string(msgs[0].Payload)
	for _, want := range []string{"[MEDIUM] PostgreSQL 17", "17.12 for your version (all fixes: 18.7, 17.12", "Not exposed on a default setup, assuming:", "docker compose pull", "reviewed by example-reviewer", "https://www.postgresql.org/support/security/CVE-2026-120154/"} {
		if !strings.Contains(s, want) {
			t.Errorf("payload lacks %q", want)
		}
	}
}

func TestSlackLimitsAndEscaping(t *testing.T) {
	var items []Item
	for i := 0; i < 40; i++ {
		items = append(items, hostile(t, i))
	}
	items[0].Advisory.Title = "a <b> & c"
	msgs, err := Slack{}.Render(items, Digest, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) < 3 {
		t.Fatalf("%d messages for 40 items", len(msgs))
	}
	for i, m := range msgs {
		var sm slackMessage
		if err := json.Unmarshal(m.Payload, &sm); err != nil {
			t.Fatal(err)
		}
		if len(sm.Blocks) > slackBlocksMax || sm.Text == "" {
			t.Fatalf("message %d: %d blocks", i, len(sm.Blocks))
		}
		for _, b := range sm.Blocks {
			if b.Text != nil && utf8.RuneCountInString(b.Text.Text) > slackSectionMax {
				t.Fatal("section too long")
			}
		}
		if strings.Contains(string(m.Payload), "<!channel>") {
			t.Fatal("slack mention not defused")
		}
	}
	var first slackMessage
	_ = json.Unmarshal(msgs[0].Payload, &first)
	if !strings.Contains(first.Blocks[0].Text.Text, `a &lt;b&gt; &amp; c`) {
		t.Fatal("not escaped")
	}
}

func TestWebhookPayload(t *testing.T) {
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	it := fixtureItem(t)
	it.Urgent = UrgentKEV
	msgs, err := Webhook{}.Render([]Item{it, it}, Digest, now)
	if err != nil || len(msgs) != 1 {
		t.Fatal(msgs, err)
	}
	var p map[string]any
	if err := json.Unmarshal(msgs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	items := p["items"].([]any)
	first := items[0].(map[string]any)
	if p["schema"] != WebhookSchema || p["kind"] != "digest" || p["sent_at"] != "2026-11-16T08:00:00Z" || len(items) != 2 {
		t.Fatalf("payload = %v", p)
	}
	for _, key := range []string{"advisory_id", "aliases", "title", "summary", "url", "product", "product_name", "declared_version", "verdict", "reason", "urgent", "severity", "kev", "epss", "fixed_in", "fix", "published_at", "revision", "note"} {
		if _, ok := first[key]; !ok {
			t.Errorf("item lacks %q", key)
		}
	}
	if first["verdict"] != "affected" || first["urgent"] != "kev" {
		t.Errorf("item = %v", first)
	}
}

func TestValidateURL(t *testing.T) {
	cases := []struct {
		typ, url string
		ok       bool
	}{
		{"discord", "https://webhooks.example.invalid/x", true},
		{"discord", "http://webhooks.example.invalid/x", false},
		{"webhook", "http://ntfy.local/topic", true},
		{"slack", "not a url", false},
		{"webhook", "", false},
	}
	for _, tc := range cases {
		err := ValidateURL(tc.typ, tc.url)
		if (err == nil) != tc.ok {
			t.Errorf("%s %q: %v", tc.typ, tc.url, err)
		}
		if err != nil && tc.url != "" && strings.Contains(err.Error(), tc.url) {
			t.Errorf("error repeats the URL: %v", err)
		}
	}
}

type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d > 0 {
		s.d = append(s.d, d)
	}
	return ctx.Err()
}

func newSender(_ *testing.T, h *testfeed.Hook, logs io.Writer) (*Sender, *sleeps) {
	sl := &sleeps{}
	return &Sender{HTTP: h.Server.Client(), Log: slog.New(slog.NewJSONHandler(logs, nil)), Sleep: sl.sleep, BaseBackoff: time.Millisecond, MaxBackoff: 4 * time.Millisecond}, sl
}

func target(h *testfeed.Hook) Target {
	return Target{ID: "discord:DISCORD_WEBHOOK_URL:ops", Type: "discord", Name: "ops", URLEnv: "DISCORD_WEBHOOK_URL", URL: h.URL()}
}

func TestPost429RetryAfter(t *testing.T) {
	h := testfeed.NewHook(t)
	h.Respond = func(n int, w http.ResponseWriter) {
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"You are being rate limited.","retry_after":0.05,"global":false}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	var logs bytes.Buffer
	s, sl := newSender(t, h, &logs)
	out, status, err := s.Post(context.Background(), target(h), []byte(`{}`))
	if out != Sent || status != 204 || err != nil {
		t.Fatalf("%s %d %v", out, status, err)
	}
	if len(h.Bodies()) != 2 {
		t.Fatalf("%d requests", len(h.Bodies()))
	}
	if len(sl.d) != 1 || sl.d[0] < 30*time.Millisecond || sl.d[0] > 50*time.Millisecond {
		t.Fatalf("waits = %v, want about 50ms", sl.d)
	}
	if strings.Contains(logs.String(), "fake-token") {
		t.Fatal("log leaks the webhook URL")
	}
}

func TestPost429HeaderAndTooLong(t *testing.T) {
	h := testfeed.NewHook(t)
	h.Respond = func(_ int, w http.ResponseWriter) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	s, _ := newSender(t, h, io.Discard)
	s.MaxWait = time.Minute
	out, _, err := s.Post(context.Background(), target(h), []byte(`{}`))
	if out != Failed || err == nil {
		t.Fatalf("%s %v", out, err)
	}
	if len(h.Bodies()) != 1 {
		t.Fatalf("%d requests, want 1 then give up", len(h.Bodies()))
	}
}

func TestPostServerErrorsBackOff(t *testing.T) {
	h := testfeed.NewHook(t)
	h.Respond = func(n int, w http.ResponseWriter) {
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	s, sl := newSender(t, h, io.Discard)
	if out, _, err := s.Post(context.Background(), target(h), []byte(`{}`)); out != Sent {
		t.Fatalf("%s %v", out, err)
	}
	if len(sl.d) != 2 || sl.d[1] < sl.d[0]/2 {
		t.Fatalf("backoff waits = %v", sl.d)
	}

	h.Respond = func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }
	s.MaxAttempts = 3
	if out, _, _ := s.Post(context.Background(), target(h), []byte(`{}`)); out != Failed {
		t.Fatalf("%s, want failed", out)
	}
}

func TestPost400Dropped(t *testing.T) {
	h := testfeed.NewHook(t)
	h.Respond = func(_ int, w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"Invalid Form Body"}`))
	}
	s, _ := newSender(t, h, io.Discard)
	out, status, err := s.Post(context.Background(), target(h), []byte(`{}`))
	if out != Dropped || status != 400 || !strings.Contains(err.Error(), "Invalid Form Body") || len(h.Bodies()) != 1 {
		t.Fatalf("%s %d %v", out, status, err)
	}
}

func TestDispatch404DisablesAndStops(t *testing.T) {
	dead := testfeed.NewHook(t)
	dead.Respond = func(_ int, w http.ResponseWriter) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Unknown Webhook","code":10015}`))
	}
	alive := testfeed.NewHook(t)
	var logs bytes.Buffer
	s, _ := newSender(t, dead, &logs)
	s.HTTP.Transport = multiTLS(t, dead, alive)

	var mu sync.Mutex
	sent, disabled := 0, 0
	jobs := func() []Job {
		var js []Job
		for i := 0; i < 3; i++ {
			js = append(js, Job{Message: Message{Payload: []byte(`{}`), Items: []Item{{}}}, OnSent: func() { mu.Lock(); sent++; mu.Unlock() }})
		}
		return js
	}
	aliveTarget := Target{ID: "slack:SLACK_WEBHOOK_URL:", Type: "slack", URLEnv: "SLACK_WEBHOOK_URL", URL: alive.URL()}
	s.Dispatch(context.Background(), []Queue{
		{Target: target(dead), Jobs: jobs(), OnDisabled: func(status int) { mu.Lock(); disabled = status; mu.Unlock() }},
		{Target: aliveTarget, Jobs: jobs()},
	})
	if len(dead.Bodies()) != 1 {
		t.Fatalf("dead webhook got %d requests, want exactly 1", len(dead.Bodies()))
	}
	if disabled != 404 || sent != 3 || len(alive.Bodies()) != 3 {
		t.Fatalf("disabled %d, sent %d, alive %d", disabled, sent, len(alive.Bodies()))
	}
	l := logs.String()
	if !strings.Contains(l, "webhook disabled") || !strings.Contains(l, "DISCORD_WEBHOOK_URL") || strings.Contains(l, "fake-token") {
		t.Fatalf("logs = %s", l)
	}
}

func TestRedactsNetworkErrors(t *testing.T) {
	h := testfeed.NewHook(t)
	tg := target(h)
	h.Server.Close()
	var logs bytes.Buffer
	s, _ := newSender(t, h, &logs)
	s.MaxAttempts = 2
	out, _, err := s.Post(context.Background(), tg, []byte(`{}`))
	if out != Failed || err == nil {
		t.Fatalf("%s %v", out, err)
	}
	if strings.Contains(err.Error(), "fake-token") || strings.Contains(logs.String(), "fake-token") {
		t.Fatalf("URL leaked: %v / %s", err, logs.String())
	}
}

// multiTLS returns a transport trusting both test servers.
func multiTLS(t *testing.T, a, b *testfeed.Hook) http.RoundTripper {
	t.Helper()
	ta := a.Server.Client().Transport.(*http.Transport).Clone()
	pool := ta.TLSClientConfig.RootCAs
	pool.AddCert(b.Server.Certificate())
	return ta
}
