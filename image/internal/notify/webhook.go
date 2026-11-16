package notify

import (
	"encoding/json"
	"time"

	"github.com/Shironex/advisorydeck/image/internal/feed"
)

// WebhookSchema marks the generic JSON payload. Fields may be added within v1; none are
// renamed or removed. The shape is documented in docs/image.md.
const WebhookSchema = "advisorydeck/v1/notification"

// Webhook renders the generic JSON payload, for ntfy, Gotify, n8n and the like.
type Webhook struct{}

// SummaryKind marks the first-start summary in the generic payload.
const SummaryKind Kind = "summary"

// WebhookPayload is the generic webhook body. An instant post carries one bundle and its
// items, a digest every pending bundle and item, a summary the per-product overview (and the
// items it covers).
type WebhookPayload struct {
	Schema  string          `json:"schema"`
	Kind    Kind            `json:"kind"`
	SentAt  time.Time       `json:"sent_at"`
	Items   []WebhookItem   `json:"items"`
	Bundle  *WebhookBundle  `json:"bundle,omitempty"`
	Bundles []WebhookBundle `json:"bundles,omitempty"`
	Summary *WebhookSummary `json:"summary,omitempty"`
}

// WebhookBundle groups the advisories one release fixes for the declared version.
type WebhookBundle struct {
	Key             string        `json:"key"`
	Product         string        `json:"product"`
	DeclaredVersion string        `json:"declared_version"`
	Fix             string        `json:"fix"`
	Latest          string        `json:"latest"`
	Action          string        `json:"action"`
	Advisories      []string      `json:"advisories"`
	Highest         feed.Severity `json:"highest"`
	Urgent          string        `json:"urgent"`
}

// WebhookSummary is the first-start overview.
type WebhookSummary struct {
	MinSeverity string                  `json:"min_severity"`
	Mode        string                  `json:"mode"`
	Backlog     bool                    `json:"backlog"`
	Products    []WebhookProductSummary `json:"products"`
}

// WebhookProductSummary is one watched product in the summary.
type WebhookProductSummary struct {
	Product         string        `json:"product"`
	ProductName     string        `json:"product_name"`
	DeclaredVersion string        `json:"declared_version"`
	Branch          bool          `json:"branch"`
	Missing         bool          `json:"missing"`
	Advisories      int           `json:"advisories"`
	Open            []string      `json:"open"`
	Releases        int           `json:"releases"`
	Latest          string        `json:"latest"`
	Action          string        `json:"action"`
	Highest         feed.Severity `json:"highest"`
}

// WebhookItem is one advisory for one declared product.
type WebhookItem struct {
	AdvisoryID      string        `json:"advisory_id"`
	Aliases         []string      `json:"aliases"`
	Title           string        `json:"title"`
	Summary         string        `json:"summary"`
	URL             string        `json:"url"`
	Product         string        `json:"product"`
	ProductName     string        `json:"product_name"`
	DeclaredVersion string        `json:"declared_version"`
	Verdict         string        `json:"verdict"`
	Reason          string        `json:"reason"`
	Urgent          string        `json:"urgent"`
	Severity        feed.Severity `json:"severity"`
	KEV             bool          `json:"kev"`
	KEVState        string        `json:"kev_state"`
	EPSS            *feed.EPSS    `json:"epss"`
	FixedIn         []string      `json:"fixed_in"`
	Fix             string        `json:"fix"`
	PublishedAt     time.Time     `json:"published_at"`
	Revision        string        `json:"revision"`
	Note            *feed.Note    `json:"note"`
}

func webhookItems(items []Item) []WebhookItem {
	out := make([]WebhookItem, 0, len(items))
	for _, it := range items {
		a := it.Advisory
		aliases := a.Aliases
		if aliases == nil {
			aliases = []string{}
		}
		out = append(out, WebhookItem{
			AdvisoryID:      a.ID,
			Aliases:         aliases,
			Title:           a.Title,
			Summary:         a.Summary,
			URL:             link(a),
			Product:         it.Product.Slug,
			ProductName:     it.Product.Name,
			DeclaredVersion: it.Declared,
			Verdict:         string(it.Verdict),
			Reason:          it.Reason,
			Urgent:          it.Urgent,
			Severity:        a.Severity,
			KEV:             a.KEV.Listed,
			KEVState:        a.KEV.State(),
			EPSS:            a.EPSS,
			FixedIn:         fixedIn(it),
			Fix:             it.FixedIn,
			PublishedAt:     a.PublishedAt,
			Revision:        a.Revision,
			Note:            a.Note,
		})
	}
	return out
}

func webhookBundle(b Bundle) WebhookBundle {
	ids := make([]string, 0, len(b.Items))
	for _, it := range b.Items {
		ids = append(ids, it.Advisory.ID)
	}
	return WebhookBundle{
		Key: b.Key, Product: b.Product.Slug, DeclaredVersion: b.Declared, Fix: b.Fix, Latest: b.Latest,
		Action: actionText(b.Declared, b.Branch, b.Latest), Advisories: ids, Highest: b.Highest(), Urgent: b.Urgent(),
	}
}

func webhookMessage(p WebhookPayload, items []Item) ([]Message, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return []Message{{Payload: raw, Items: items}}, nil
}

// Bundle implements Renderer: one payload with the bundle and its items.
func (Webhook) Bundle(b Bundle, now time.Time) ([]Message, error) {
	wb := webhookBundle(b)
	return webhookMessage(WebhookPayload{Schema: WebhookSchema, Kind: Instant, SentAt: now.UTC(), Items: webhookItems(b.Items), Bundle: &wb}, b.Items)
}

// Group implements Renderer: one instant payload with the product's bundles.
func (Webhook) Group(d ProductDigest, now time.Time) ([]Message, error) {
	bundles := make([]WebhookBundle, 0, len(d.Bundles))
	for _, b := range d.Bundles {
		bundles = append(bundles, webhookBundle(b))
	}
	items := d.Items()
	return webhookMessage(WebhookPayload{Schema: WebhookSchema, Kind: Instant, SentAt: now.UTC(), Items: webhookItems(items), Bundles: bundles}, items)
}

// Digest implements Renderer: one payload holding every pending bundle and item.
func (Webhook) Digest(ds []ProductDigest, now time.Time) ([]Message, error) {
	var items []Item
	bundles := []WebhookBundle{}
	for _, d := range ds {
		for _, b := range d.Bundles {
			bundles = append(bundles, webhookBundle(b))
			items = append(items, b.Items...)
		}
	}
	return webhookMessage(WebhookPayload{Schema: WebhookSchema, Kind: Digest, SentAt: now.UTC(), Items: webhookItems(items), Bundles: bundles}, items)
}

// Summary implements Renderer: one payload with the overview; items lists what it covers.
func (Webhook) Summary(s Summary, now time.Time) ([]Message, error) {
	ws := WebhookSummary{MinSeverity: s.MinSeverity, Mode: s.Mode, Backlog: s.Backlog, Products: []WebhookProductSummary{}}
	for _, p := range s.Products {
		open := make([]string, 0, len(p.Items))
		for _, it := range p.Items {
			open = append(open, it.Advisory.ID)
		}
		action := ""
		if len(p.Items) > 0 {
			action = actionText(p.Declared, p.Branch, p.Latest)
		}
		ws.Products = append(ws.Products, WebhookProductSummary{
			Product: p.Product.Slug, ProductName: p.Product.Name, DeclaredVersion: p.Declared, Branch: p.Branch,
			Missing: p.Missing, Advisories: p.Advisories, Open: open, Releases: p.Releases, Latest: p.Latest,
			Action: action, Highest: highestOf(p.Items),
		})
	}
	items := s.Items()
	return webhookMessage(WebhookPayload{Schema: WebhookSchema, Kind: SummaryKind, SentAt: now.UTC(), Items: webhookItems(items), Summary: &ws}, items)
}
