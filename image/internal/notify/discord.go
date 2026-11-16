package notify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Discord message limits (characters are counted as runes).
const (
	discordTitleMax       = 256
	discordDescriptionMax = 4096
	discordFieldsMax      = 25
	discordFieldNameMax   = 256
	discordFieldValueMax  = 1024
	discordFooterMax      = 2048
	discordEmbedsMax      = 10
	discordTotalMax       = 6000
	discordContentMax     = 2000
)

// Discord renders embeds for a Discord webhook.
type Discord struct{}

type discordMessage struct {
	Content         string          `json:"content,omitempty"`
	Username        string          `json:"username,omitempty"`
	Embeds          []discordEmbed  `json:"embeds"`
	AllowedMentions allowedMentions `json:"allowed_mentions"`
}

type allowedMentions struct {
	Parse []string `json:"parse"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	URL         string         `json:"url,omitempty"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields,omitempty"`
	Footer      *discordFooter `json:"footer,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordFooter struct {
	Text string `json:"text"`
}

var discordColors = map[string]int{"critical": 0xB00020, "high": 0xE8590C, "medium": 0xF2C94C, "low": 0x2F80ED}

// size counts the characters Discord adds up against the 6000 limit.
func (e discordEmbed) size() int {
	n := utf8.RuneCountInString(e.Title) + utf8.RuneCountInString(e.Description)
	for _, f := range e.Fields {
		n += utf8.RuneCountInString(f.Name) + utf8.RuneCountInString(f.Value)
	}
	if e.Footer != nil {
		n += utf8.RuneCountInString(e.Footer.Text)
	}
	return n
}

func discordEmbedFor(it Item, kind Kind) discordEmbed {
	a := it.Advisory
	descMax := 1500
	if kind == Digest {
		descMax = 300
	}
	e := discordEmbed{
		Title:       truncate(defuse(headline(it)), discordTitleMax),
		URL:         link(a),
		Description: truncate(defuse(a.Summary), descMax),
		Color:       0x828282,
		Timestamp:   a.PublishedAt.UTC().Format(time.RFC3339),
	}
	if c, ok := discordColors[a.Severity.Level]; ok {
		e.Color = c
	}
	field := func(name, value string, inline bool) {
		if len(e.Fields) >= discordFieldsMax || strings.TrimSpace(value) == "" {
			return
		}
		e.Fields = append(e.Fields, discordField{
			Name:   truncate(name, discordFieldNameMax),
			Value:  truncate(defuse(value), discordFieldValueMax),
			Inline: inline,
		})
	}
	field("Upstream", upstreamText(it.Product), false)
	field("Your version", fmt.Sprintf("%s: %s", it.Declared, it.Reason), false)
	field("Fixed in", fixText(it), true)
	field("Severity", severityText(a.Severity), true)
	if kind == Instant {
		field("Exploitation", exploitText(a), false)
		field("IDs", ids(a), false)
	}
	footer := "Advisorydeck, data: " + sourceNames(it)
	if n := a.Note; n != nil {
		field("Exposure", exposureText(n), false)
		if kind == Instant {
			field("Do this", actionLines(n, true), false)
		}
		footer += fmt.Sprintf(", note reviewed by %s on %s", n.ReviewedBy, n.ReviewedAt)
	}
	e.Footer = &discordFooter{Text: truncate(defuse(footer), discordFooterMax)}
	return fitEmbed(e, discordTotalMax)
}

// fitEmbed shortens the longest text of an embed until it fits limit characters.
func fitEmbed(e discordEmbed, limit int) discordEmbed {
	for e.size() > limit {
		excess := e.size() - limit
		longest := &e.Description
		for i := range e.Fields {
			if utf8.RuneCountInString(e.Fields[i].Value) > utf8.RuneCountInString(*longest) {
				longest = &e.Fields[i].Value
			}
		}
		n := utf8.RuneCountInString(*longest)
		if n <= 20 {
			break
		}
		keep := n - excess
		if keep < 20 {
			keep = 20
		}
		*longest = truncate(*longest, keep)
	}
	return e
}

func sourceNames(it Item) string {
	seen := map[string]bool{}
	var out []string
	for _, s := range it.Advisory.Sources {
		label := s.Type
		if s.License != "" {
			label += " (" + s.License + ")"
		}
		if !seen[label] {
			seen[label] = true
			out = append(out, label)
		}
	}
	if len(out) == 0 {
		return "see the advisory"
	}
	return strings.Join(out, ", ")
}

func newDiscordMessage(content string) discordMessage {
	return discordMessage{Content: truncate(defuse(content), discordContentMax), Username: "Advisorydeck", AllowedMentions: allowedMentions{Parse: []string{}}}
}

func discordColor(level string) int {
	if c, ok := discordColors[level]; ok {
		return c
	}
	return 0x828282
}

func (e *discordEmbed) addField(name, value string, inline bool) {
	if len(e.Fields) >= discordFieldsMax || strings.TrimSpace(value) == "" {
		return
	}
	e.Fields = append(e.Fields, discordField{
		Name:   truncate(defuse(name), discordFieldNameMax),
		Value:  truncate(defuse(value), discordFieldValueMax),
		Inline: inline,
	})
}

// discordBundleEmbed renders a bundle: a single advisory in full, several as a collapsed list.
func discordBundleEmbed(b Bundle) discordEmbed {
	if len(b.Items) == 1 {
		e := discordEmbedFor(b.Items[0], Instant)
		if b.Latest != "" && b.Latest != b.Items[0].FixedIn {
			e.addField("Newest release you need", actionText(b.Declared, b.Branch, b.Latest), false)
		}
		return fitEmbed(e, discordTotalMax)
	}
	first := b.Items[0].Advisory
	lead := bundleLead(b)
	e := discordEmbed{
		Title:     truncate(defuse(bundleTitle(b)), discordTitleMax),
		URL:       link(first),
		Color:     discordColor(b.Highest().Level),
		Timestamp: first.PublishedAt.UTC().Format(time.RFC3339),
	}
	list := collapsedList(b.Items, discordDescriptionMax-runeLen(lead)-200, itemLine)
	e.Description = truncate(defuse(lead+"\n\n"+list), discordDescriptionMax)
	e.addField("Exploitation", exploitSummary(b.Items), false)
	for i, it := range notedItems(b.Items) {
		if i == 3 {
			break
		}
		e.addField("Exposure, "+it.Advisory.ID, exposureText(it.Advisory.Note), false)
	}
	e.Footer = &discordFooter{Text: truncate(defuse("Advisorydeck, data: "+bundleSources(b.Items)), discordFooterMax)}
	return fitEmbed(e, discordTotalMax)
}

func discordDigestEmbed(d ProductDigest, budget int) discordEmbed {
	items := d.Items()
	head := withUpstream(d.Product, actionText(d.Declared, d.Branch, d.Latest))
	lines := make([]string, 0, len(d.Bundles))
	for _, b := range d.Bundles {
		lines = append(lines, digestLine(b))
	}
	limit := min(discordDescriptionMax, budget-300)
	list := collapsedLines(lines, limit-runeLen(head)-2)
	e := discordEmbed{
		Title:       truncate(defuse(fmt.Sprintf("[%s] %s: %s", levelLabel(highestOf(items).Level), productTitle(d.Product, d.Declared, d.Branch), plural(len(items), "advisory", "advisories"))), discordTitleMax),
		Description: truncate(defuse(head+"\n\n"+list), discordDescriptionMax),
		Color:       discordColor(highestOf(items).Level),
	}
	e.Footer = &discordFooter{Text: truncate(defuse("Advisorydeck, data: "+bundleSources(items)), discordFooterMax)}
	return fitEmbed(e, budget)
}

func discordSummaryEmbed(p ProductSummary, floor string, budget int) discordEmbed {
	e := discordEmbed{
		Title:       truncate(defuse(productTitle(p.Product, p.Declared, p.Branch)), discordTitleMax),
		Description: truncate(defuse(summaryText(p, floor)), discordDescriptionMax),
		Color:       discordColor(highestOf(p.Items).Level),
	}
	if len(p.Items) == 0 {
		e.Color = 0x2E7D32
	}
	return fitEmbed(e, budget)
}

// Bundle implements Renderer: one message with one embed.
func (Discord) Bundle(b Bundle, _ time.Time) ([]Message, error) {
	m := newDiscordMessage("")
	m.Embeds = []discordEmbed{discordBundleEmbed(b)}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return []Message{{Payload: raw, Items: b.Items}}, nil
}

// Group implements Renderer: one message with the product's embed.
func (Discord) Group(d ProductDigest, _ time.Time) ([]Message, error) {
	m := newDiscordMessage(groupIntro(d))
	m.Embeds = []discordEmbed{discordDigestEmbed(d, discordTotalMax)}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return []Message{{Payload: raw, Items: d.Items()}}, nil
}

// Digest implements Renderer: one embed per product, split over messages so each stays
// within 10 embeds and 6000 characters.
func (Discord) Digest(ds []ProductDigest, _ time.Time) ([]Message, error) {
	var out []Message
	cur := newDiscordMessage(digestIntro(ds))
	var curItems []Item
	total := 0
	flush := func() error {
		if len(cur.Embeds) == 0 {
			return nil
		}
		raw, err := json.Marshal(cur)
		if err != nil {
			return err
		}
		out = append(out, Message{Payload: raw, Items: curItems})
		cur, curItems, total = newDiscordMessage(""), nil, 0
		return nil
	}
	for _, d := range ds {
		e := discordDigestEmbed(d, discordTotalMax)
		if len(cur.Embeds) == discordEmbedsMax || total+e.size() > discordTotalMax {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		cur.Embeds = append(cur.Embeds, e)
		curItems = append(curItems, d.Items()...)
		total += e.size()
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// Summary implements Renderer: always one message. Products with open advisories get an
// embed each (most severe first); past nine, the rest share one embed of one-line entries.
func (Discord) Summary(s Summary, _ time.Time) ([]Message, error) {
	m := newDiscordMessage(summaryIntro(s))
	products := append([]ProductSummary(nil), s.Products...)
	sort.SliceStable(products, func(i, j int) bool {
		return SeverityRank(highestOf(products[i].Items).Level) > SeverityRank(highestOf(products[j].Items).Level) ||
			(SeverityRank(highestOf(products[i].Items).Level) == SeverityRank(highestOf(products[j].Items).Level) && len(products[i].Items) > len(products[j].Items))
	})
	full, rest := products, []ProductSummary(nil)
	if len(products) > discordEmbedsMax {
		full, rest = products[:discordEmbedsMax-1], products[discordEmbedsMax-1:]
	}
	n := len(full)
	if len(rest) > 0 {
		n++
	}
	budget := (discordTotalMax - 100) / n
	for _, p := range full {
		m.Embeds = append(m.Embeds, discordSummaryEmbed(p, s.MinSeverity, budget))
	}
	if len(rest) > 0 {
		var b strings.Builder
		for _, p := range rest {
			b.WriteString(productTitle(p.Product, p.Declared, p.Branch) + ": " + SummaryLine(p) + "\n")
		}
		e := discordEmbed{Title: fmt.Sprintf("%d more products", len(rest)), Description: truncate(defuse(b.String()), discordDescriptionMax), Color: 0x828282}
		m.Embeds = append(m.Embeds, fitEmbed(e, budget))
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return []Message{{Payload: raw, Items: s.Items()}}, nil
}
