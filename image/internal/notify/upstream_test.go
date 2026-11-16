package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/advisorydeck/image/internal/feed"
)

// archivedItem is the fixture item for a product whose upstream is archived.
func archivedItem(t *testing.T) Item {
	it := fixtureItem(t)
	it.Product.Upstream = &feed.Upstream{Status: feed.UpstreamArchived, Since: "2026-07-01", Note: "A maintained fork exists."}
	return it
}

func TestUpstreamText(t *testing.T) {
	p := feed.ProductInfo{Slug: "x", Name: "Example"}
	if got := upstreamText(p); got != "" || upstreamBadge(p) != "" {
		t.Fatalf("maintained product got %q %q", got, upstreamBadge(p))
	}
	p.Upstream = &feed.Upstream{Status: feed.UpstreamArchived, Since: "2026-07-01", Note: "See the fork."}
	want := "Upstream archived Example on 2026-07-01, so no further fixes are expected: plan a move to a maintained alternative. See the fork."
	if got := upstreamText(p); got != want {
		t.Fatalf("got %q", got)
	}
	p.Upstream = &feed.Upstream{Status: feed.UpstreamArchived}
	if got := upstreamText(p); !strings.HasPrefix(got, "Upstream archived Example, so no further fixes") {
		t.Fatalf("without a date: %q", got)
	}
	// A status from a newer feed is still shown, never dropped.
	p.Upstream = &feed.Upstream{Status: "retired", Since: "2027-01-01"}
	if got := upstreamText(p); got != "Upstream status of Example: retired. Since 2027-01-01." || upstreamBadge(p) != " [UPSTREAM RETIRED]" {
		t.Fatalf("unknown status: %q %q", got, upstreamBadge(p))
	}
}

// Every message kind about an archived product carries the warning, on every channel type.
func TestUpstreamInEveryMessage(t *testing.T) {
	it := archivedItem(t)
	second := it
	second.Advisory.ID = "GHSA-aaaa-bbbb-cccc"
	single := Bundle{Key: BundleKey("postgresql", "17.12", ""), Product: it.Product, Declared: "17", Branch: true, Fix: "17.12", Latest: "17.12", Items: []Item{it}}
	multi := single
	multi.Items = []Item{it, second}
	digest := ProductDigest{Product: it.Product, Declared: "17", Branch: true, Latest: "17.12", Bundles: []Bundle{single}}
	summary := Summary{MinSeverity: "high", Mode: "digest", Products: []ProductSummary{
		{Product: it.Product, Declared: "17", Branch: true, Advisories: 96, Items: []Item{it}, Latest: "17.12", Releases: 1},
		{Product: it.Product, Declared: "16", Advisories: 96},
	}}
	now := time.Now()
	for _, r := range []Renderer{Discord{}, Slack{}} {
		for name, render := range map[string]func() ([]Message, error){
			"single":  func() ([]Message, error) { return r.Bundle(single, now) },
			"bundle":  func() ([]Message, error) { return r.Bundle(multi, now) },
			"group":   func() ([]Message, error) { return r.Group(digest, now) },
			"digest":  func() ([]Message, error) { return r.Digest([]ProductDigest{digest}, now) },
			"summary": func() ([]Message, error) { return r.Summary(summary, now) },
		} {
			msgs, err := render()
			if err != nil || len(msgs) == 0 {
				t.Fatalf("%T %s: %v", r, name, err)
			}
			p := string(msgs[0].Payload)
			for _, want := range []string{"[UPSTREAM ARCHIVED]", "Upstream archived PostgreSQL on 2026-07-01", "A maintained fork exists."} {
				if !strings.Contains(p, want) {
					t.Errorf("%T %s lacks %q:\n%s", r, name, want, p)
				}
			}
		}
	}
	// A summary with nothing open still says it.
	quiet := Summary{MinSeverity: "high", Mode: "digest", Products: []ProductSummary{{Product: it.Product, Declared: "17", Advisories: 3}}}
	msgs, err := Discord{}.Summary(quiet, now)
	if err != nil || !strings.Contains(string(msgs[0].Payload), "Upstream archived PostgreSQL") {
		t.Fatalf("quiet summary: %v %s", err, msgs[0].Payload)
	}
}

func TestUpstreamInWebhookPayload(t *testing.T) {
	it := archivedItem(t)
	b := Bundle{Key: BundleKey("postgresql", "17.12", ""), Product: it.Product, Declared: "17", Branch: true, Fix: "17.12", Latest: "17.12", Items: []Item{it}}
	msgs, err := Webhook{}.Bundle(b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var p WebhookPayload
	if err := json.Unmarshal(msgs[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Bundle.Upstream == nil || p.Bundle.Upstream.Since != "2026-07-01" || p.Items[0].Upstream == nil || p.Items[0].Upstream.Status != "archived" {
		t.Fatalf("payload: %s", msgs[0].Payload)
	}
	s := Summary{MinSeverity: "high", Mode: "digest", Products: []ProductSummary{{Product: it.Product, Declared: "17", Advisories: 3}}}
	msgs, err = Webhook{}.Summary(s, time.Now())
	if err != nil || !strings.Contains(string(msgs[0].Payload), `"upstream":{"status":"archived","since":"2026-07-01"`) {
		t.Fatalf("summary payload: %v %s", err, msgs[0].Payload)
	}
	// A maintained product has no upstream key at all.
	plain := fixtureItem(t)
	msgs, err = Webhook{}.Bundle(Bundle{Key: "k", Product: plain.Product, Declared: "17", Items: []Item{plain}}, time.Now())
	if err != nil || strings.Contains(string(msgs[0].Payload), `"upstream"`) {
		t.Fatalf("maintained payload: %v %s", err, msgs[0].Payload)
	}
}
