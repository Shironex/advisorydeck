package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// hostileBundle is a release bundle of n hostile items for one product.
func hostileBundle(t *testing.T, n int, product string) Bundle {
	var items []Item
	for i := 0; i < n; i++ {
		it := hostile(t, i)
		it.Advisory.ID = fmt.Sprintf("CVE-2026-%d", 100000+i)
		it.Key = Key(it.Advisory.ID, product)
		it.Product.Slug = product
		it.Product.Name = "@everyone " + strings.Repeat("N", 300)
		items = append(items, it)
	}
	info := feed.ProductInfo{Slug: product, Name: "@everyone " + strings.Repeat("N", 300)}
	return Bundle{Key: BundleKey(product, "17.12", ""), Product: info, Declared: "17", Branch: true, Fix: "17.12", Latest: "17.13", Items: items}
}

// checkDiscord decodes a Discord payload and fails on any limit it breaks.
func checkDiscord(t *testing.T, m Message) discordMessage {
	t.Helper()
	var dm discordMessage
	if err := json.Unmarshal(m.Payload, &dm); err != nil {
		t.Fatal(err)
	}
	if dm.AllowedMentions.Parse == nil || len(dm.AllowedMentions.Parse) != 0 || !strings.Contains(string(m.Payload), `"allowed_mentions":{"parse":[]}`) {
		t.Fatalf("allowed_mentions missing: %.200s", m.Payload)
	}
	if len(dm.Embeds) == 0 || len(dm.Embeds) > discordEmbedsMax {
		t.Fatalf("%d embeds", len(dm.Embeds))
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
		if e.Footer != nil && utf8.RuneCountInString(e.Footer.Text) > discordFooterMax {
			t.Fatal("footer too long")
		}
		if strings.Contains(e.Title, "@everyone") || strings.Contains(e.Description, "@here") || strings.Contains(e.Description, "@everyone") {
			t.Fatal("mention not defused")
		}
	}
	if total > discordTotalMax {
		t.Fatalf("message has %d characters", total)
	}
	return dm
}

// checkSlack decodes a Slack payload and fails on any limit it breaks.
func checkSlack(t *testing.T, m Message) slackMessage {
	t.Helper()
	var sm slackMessage
	if err := json.Unmarshal(m.Payload, &sm); err != nil {
		t.Fatal(err)
	}
	if len(sm.Blocks) == 0 || len(sm.Blocks) > slackBlocksMax || sm.Text == "" || utf8.RuneCountInString(sm.Text) > slackTextMax {
		t.Fatalf("%d blocks, text %d", len(sm.Blocks), utf8.RuneCountInString(sm.Text))
	}
	for _, b := range sm.Blocks {
		if b.Text != nil && utf8.RuneCountInString(b.Text.Text) > slackSectionMax {
			t.Fatal("section too long")
		}
		for _, el := range b.Elements {
			if utf8.RuneCountInString(el.Text) > slackContextMax {
				t.Fatal("context too long")
			}
		}
	}
	if strings.Contains(string(m.Payload), "<!channel>") || strings.Contains(string(m.Payload), "@everyone") {
		t.Fatal("slack mention not defused")
	}
	return sm
}

func TestBundleLimits(t *testing.T) {
	for _, n := range []int{1, 2, 96} {
		b := hostileBundle(t, n, "postgresql")
		msgs, err := Discord{}.Bundle(b, time.Now())
		if err != nil || len(msgs) != 1 || len(msgs[0].Items) != n {
			t.Fatalf("discord: %d messages, err %v", len(msgs), err)
		}
		if dm := checkDiscord(t, msgs[0]); len(dm.Embeds) != 1 {
			t.Fatalf("bundle of %d: %d embeds, want 1", n, len(dm.Embeds))
		}
		msgs, err = Slack{}.Bundle(b, time.Now())
		if err != nil || len(msgs) != 1 || len(msgs[0].Items) != n {
			t.Fatalf("slack: %d messages, err %v", len(msgs), err)
		}
		checkSlack(t, msgs[0])
	}
}

func TestDigestLimits(t *testing.T) {
	var ds []ProductDigest
	total := 0
	for p := 0; p < 23; p++ {
		slug := fmt.Sprintf("product-%d", p)
		d := ProductDigest{Product: feed.ProductInfo{Slug: slug, Name: "@here " + strings.Repeat("P", 200)}, Declared: "17", Branch: true, Latest: "17.13"}
		for k := 0; k < 4; k++ {
			b := hostileBundle(t, 1+k*10, slug)
			b.Fix = fmt.Sprintf("17.%d", 10+k)
			d.Bundles = append(d.Bundles, b)
			total += len(b.Items)
		}
		ds = append(ds, d)
	}
	for name, r := range map[string]Renderer{"discord": Discord{}, "slack": Slack{}} {
		msgs, err := r.Digest(ds, time.Now())
		if err != nil || len(msgs) < 2 {
			t.Fatalf("%s: %d messages, err %v", name, len(msgs), err)
		}
		count := 0
		for _, m := range msgs {
			if name == "discord" {
				checkDiscord(t, m)
			} else {
				checkSlack(t, m)
			}
			count += len(m.Items)
		}
		if count != total {
			t.Fatalf("%s: %d items carried, want %d", name, count, total)
		}
	}
}

func TestSummaryLimits(t *testing.T) {
	var s Summary
	s.MinSeverity, s.Mode = "high", "digest"
	for p := 0; p < 60; p++ {
		b := hostileBundle(t, p%7, fmt.Sprintf("product-%d", p))
		s.Products = append(s.Products, ProductSummary{Product: feed.ProductInfo{Slug: b.Key, Name: "@everyone " + strings.Repeat("Q", 300)}, Declared: "17", Branch: p%2 == 0, Advisories: 90, Items: b.Items, Latest: "17.12", LatestDate: time.Now(), Releases: p % 5})
	}
	for _, n := range []int{1, 9, 10, 11, 60} {
		sub := s
		sub.Products = s.Products[:n]
		msgs, err := Discord{}.Summary(sub, time.Now())
		if err != nil || len(msgs) != 1 || len(msgs[0].Items) != len(sub.Items()) {
			t.Fatalf("discord summary of %d products: %d messages, err %v", n, len(msgs), err)
		}
		checkDiscord(t, msgs[0])
		msgs, err = Slack{}.Summary(sub, time.Now())
		if err != nil || len(msgs) != 1 {
			t.Fatalf("slack summary of %d products: %d messages, err %v", n, len(msgs), err)
		}
		checkSlack(t, msgs[0])
	}
}

func TestDiscordContent(t *testing.T) {
	it := fixtureItem(t)
	b := Bundle{Key: BundleKey("postgresql", "17.12", ""), Product: it.Product, Declared: "17", Branch: true, Fix: "17.12", Latest: "17.12", Items: []Item{it}}
	msgs, err := Discord{}.Bundle(b, time.Now())
	if err != nil || len(msgs) != 1 {
		t.Fatal(msgs, err)
	}
	s := string(msgs[0].Payload)
	for _, want := range []string{"[MEDIUM] PostgreSQL 17", "17.12 for your version (all fixes: 18.7, 17.12", "Not exposed on a default setup, assuming:", "docker compose pull", "reviewed by example-reviewer", "https://www.postgresql.org/support/security/CVE-2026-120154/", "not in CISA KEV", "EPSS 0.3%"} {
		if !strings.Contains(s, want) {
			t.Errorf("payload lacks %q", want)
		}
	}
}

func TestBundleContent(t *testing.T) {
	it := fixtureItem(t)
	second := it
	second.Advisory.ID, second.Key = "CVE-2026-120153", Key("CVE-2026-120153", "postgresql")
	second.Advisory.Severity.Level = "high"
	second.Change = ChangeNew
	b := Bundle{Key: BundleKey("postgresql", "17.12", ""), Product: it.Product, Declared: "17", Branch: true, Fix: "17.12", Latest: "17.13", Items: []Item{second, it}}
	msgs, err := Discord{}.Bundle(b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := string(msgs[0].Payload)
	for _, want := range []string{"[HIGH] PostgreSQL 17.12 fixes 2 advisories for 17", "17.13 is the newest release you need", "Make sure you run 17.13 or later", "floating 17 tag", "1 high, 1 medium", "CVE-2026-120153 HIGH 4.3 (new)", "Exposure, CVE-2026-120154", "none in CISA KEV"} {
		if !strings.Contains(s, want) {
			t.Errorf("bundle lacks %q:\n%s", want, s)
		}
	}
	msgs, err = Slack{}.Bundle(b, time.Now())
	if err != nil || !strings.Contains(string(msgs[0].Payload), "PostgreSQL 17.12 fixes 2 advisories") {
		t.Fatalf("slack bundle: %v %s", err, msgs[0].Payload)
	}
}

func TestKEVNotCheckedIsNeverNotListed(t *testing.T) {
	it := fixtureItem(t)
	it.Advisory.KEV = feed.KEV{} // a feed from before enrichment
	b := Bundle{Key: "k", Product: it.Product, Declared: "17", Fix: "17.12", Latest: "17.12", Items: []Item{it}}
	for name, r := range map[string]Renderer{"discord": Discord{}, "slack": Slack{}, "webhook": Webhook{}} {
		msgs, err := r.Bundle(b, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		s := string(msgs[0].Payload)
		if strings.Contains(s, "not in CISA KEV") || strings.Contains(s, "none in CISA KEV") {
			t.Errorf("%s says not in KEV for an unchecked advisory: %s", name, s)
		}
		if name != "webhook" && !strings.Contains(s, "CISA KEV not checked") {
			t.Errorf("%s does not say KEV was not checked", name)
		}
		if name == "webhook" && !strings.Contains(s, `"kev_state":"not-checked"`) {
			t.Errorf("webhook lacks kev_state not-checked: %s", s)
		}
	}
	two := b
	two.Items = []Item{it, it}
	msgs, _ := Discord{}.Bundle(two, time.Now())
	if s := string(msgs[0].Payload); strings.Contains(s, "none in CISA KEV") || !strings.Contains(s, "CISA KEV not checked") {
		t.Errorf("bundle KEV text wrong: %s", s)
	}
}

func TestSummaryContent(t *testing.T) {
	it := fixtureItem(t)
	open := it
	open.Advisory.ID, open.FixedIn, open.Urgent = "GHSA-aaaa-bbbb-cccc", "", UrgentKEV
	s := Summary{MinSeverity: "high", Mode: "digest", Products: []ProductSummary{
		{Product: it.Product, Declared: "17", Branch: true, Advisories: 96, Items: []Item{open, it}, Latest: "17.12", LatestDate: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), Releases: 1},
		{Product: feed.ProductInfo{Slug: "traefik", Name: "Traefik"}, Declared: "3.7.19", Advisories: 70},
		{Product: feed.ProductInfo{Slug: "nope", Name: "nope"}, Declared: "1", Missing: true},
	}}
	msgs, err := Discord{}.Summary(s, time.Now())
	if err != nil || len(msgs) != 1 || len(msgs[0].Items) != 2 {
		t.Fatal(msgs, err)
	}
	p := string(msgs[0].Payload)
	for _, want := range []string{"now watching 3 products", "summarized here instead of posted one by one", "PostgreSQL 17 (branch)", "Branch 17 has 2 open advisories at high or above, fixed across 1 release", "Make sure you run 17.12 or later", "last pulled before 2026-11-12", "GHSA-aaaa-bbbb-cccc (in CISA KEV)", "check manually: GHSA-aaaa-bbbb-cccc", "Nothing open at high or above among the 70 advisories", "no file for nope"} {
		if !strings.Contains(p, want) {
			t.Errorf("summary lacks %q:\n%s", want, p)
		}
	}
	wm, err := Webhook{}.Summary(s, time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(wm[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	sum := payload["summary"].(map[string]any)
	if payload["kind"] != "summary" || len(sum["products"].([]any)) != 3 || len(payload["items"].([]any)) != 2 {
		t.Fatalf("webhook summary = %v", payload)
	}
}

func TestWebhookPayload(t *testing.T) {
	now := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	it := fixtureItem(t)
	it.Urgent = UrgentKEV
	b := Bundle{Key: BundleKey("postgresql", "17.12", ""), Product: it.Product, Declared: "17", Branch: true, Fix: "17.12", Latest: "17.12", Items: []Item{it, it}}
	msgs, err := Webhook{}.Digest([]ProductDigest{{Product: it.Product, Declared: "17", Branch: true, Latest: "17.12", Bundles: []Bundle{b}}}, now)
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
	for _, key := range []string{"advisory_id", "aliases", "title", "summary", "url", "product", "product_name", "declared_version", "verdict", "reason", "urgent", "severity", "kev", "kev_state", "epss", "fixed_in", "fix", "published_at", "revision", "note"} {
		if _, ok := first[key]; !ok {
			t.Errorf("item lacks %q", key)
		}
	}
	if first["verdict"] != "affected" || first["urgent"] != "kev" {
		t.Errorf("item = %v", first)
	}
	bundles := p["bundles"].([]any)
	wb := bundles[0].(map[string]any)
	if len(bundles) != 1 || wb["fix"] != "17.12" || wb["urgent"] != "kev" || !strings.Contains(wb["action"].(string), "17.12 or later") {
		t.Errorf("bundles = %v", bundles)
	}
	inst, err := Webhook{}.Bundle(b, now)
	if err != nil || !strings.Contains(string(inst[0].Payload), `"bundle":{"key":"postgresql|fix:17.12"`) {
		t.Fatalf("instant payload: %v %s", err, inst[0].Payload)
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
