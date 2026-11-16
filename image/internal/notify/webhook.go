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

// WebhookPayload is the generic webhook body.
type WebhookPayload struct {
	Schema string        `json:"schema"`
	Kind   Kind          `json:"kind"`
	SentAt time.Time     `json:"sent_at"`
	Items  []WebhookItem `json:"items"`
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
	EPSS            *feed.EPSS    `json:"epss"`
	FixedIn         []string      `json:"fixed_in"`
	PublishedAt     time.Time     `json:"published_at"`
	Revision        string        `json:"revision"`
	Note            *feed.Note    `json:"note"`
}

// Render implements Renderer. A digest is one payload holding every item.
func (Webhook) Render(items []Item, kind Kind, now time.Time) ([]Message, error) {
	p := WebhookPayload{Schema: WebhookSchema, Kind: kind, SentAt: now.UTC(), Items: make([]WebhookItem, 0, len(items))}
	for _, it := range items {
		a := it.Advisory
		aliases := a.Aliases
		if aliases == nil {
			aliases = []string{}
		}
		p.Items = append(p.Items, WebhookItem{
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
			EPSS:            a.EPSS,
			FixedIn:         fixedIn(it),
			PublishedAt:     a.PublishedAt,
			Revision:        a.Revision,
			Note:            a.Note,
		})
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return []Message{{Payload: raw, Items: items}}, nil
}
