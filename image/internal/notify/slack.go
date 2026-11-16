package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Slack Block Kit limits.
const (
	slackBlocksMax  = 50
	slackSectionMax = 3000
	slackContextMax = 2000
	slackTextMax    = 3000
)

// Slack renders Block Kit messages for a Slack incoming webhook.
type Slack struct{}

type slackMessage struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type     string      `json:"type"`
	Text     *slackText  `json:"text,omitempty"`
	Elements []slackText `json:"elements,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// slackEscape escapes the three characters Slack mrkdwn treats as control characters.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func slackBlocksFor(it Item, kind Kind) []slackBlock {
	a := it.Advisory
	title := slackEscape(defuse(headline(it)))
	if u := link(a); u != "" {
		title = "<" + u + "|" + title + ">"
	}
	descMax := 1200
	if kind == Digest {
		descMax = 300
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%s*\n%s\n", title, slackEscape(defuse(truncate(a.Summary, descMax))))
	fmt.Fprintf(&b, "*Your version:* %s: %s\n", slackEscape(it.Declared), slackEscape(it.Reason))
	fmt.Fprintf(&b, "*Fixed in:* %s\n", slackEscape(fixText(it)))
	fmt.Fprintf(&b, "*Severity:* %s\n", slackEscape(severityText(a.Severity)))
	if kind == Instant {
		fmt.Fprintf(&b, "*Exploitation:* %s\n", slackEscape(exploitText(a)))
	}
	if n := a.Note; n != nil {
		fmt.Fprintf(&b, "*Exposure:* %s\n", slackEscape(defuse(exposureText(n))))
		if kind == Instant && len(n.Actions) > 0 {
			fmt.Fprintf(&b, "*Do this:*\n%s\n", slackEscape(defuse(actionLines(n, true))))
		}
	}
	footer := fmt.Sprintf("%s | Advisorydeck, data: %s", ids(a), sourceNames(it))
	if n := a.Note; n != nil {
		footer += fmt.Sprintf(" | note reviewed by %s on %s", n.ReviewedBy, n.ReviewedAt)
	}
	return []slackBlock{
		{Type: "section", Text: &slackText{Type: "mrkdwn", Text: truncate(b.String(), slackSectionMax)}},
		{Type: "context", Elements: []slackText{{Type: "mrkdwn", Text: truncate(slackEscape(defuse(footer)), slackContextMax)}}},
		{Type: "divider"},
	}
}

func slackSection(text string) slackBlock {
	return slackBlock{Type: "section", Text: &slackText{Type: "mrkdwn", Text: truncate(text, slackSectionMax)}}
}

func slackContext(text string) slackBlock {
	return slackBlock{Type: "context", Elements: []slackText{{Type: "mrkdwn", Text: truncate(text, slackContextMax)}}}
}

func slackMessageBytes(text string, blocks []slackBlock) ([]byte, error) {
	return json.Marshal(slackMessage{Text: truncate(text, slackTextMax), Blocks: blocks})
}

func slackTitle(text, url string) string {
	t := slackEscape(defuse(text))
	if url != "" {
		t = "<" + url + "|" + t + ">"
	}
	return "*" + t + "*"
}

// slackBundleBlocks renders a bundle: one advisory in full, several as a collapsed list.
func slackBundleBlocks(b Bundle) []slackBlock {
	if len(b.Items) == 1 {
		blocks := slackBlocksFor(b.Items[0], Instant)
		if b.Latest != "" && b.Latest != b.Items[0].FixedIn {
			extra := slackContext("*Newest release you need:* " + slackEscape(actionText(b.Declared, b.Branch, b.Latest)))
			blocks = append(blocks[:1], append([]slackBlock{extra}, blocks[1:]...)...)
		}
		return blocks
	}
	head := slackTitle(bundleTitle(b), link(b.Items[0].Advisory)) + "\n" + slackEscape(defuse(bundleLead(b))) + "\n"
	list := slackEscape(defuse(collapsedList(b.Items, slackSectionMax-runeLen(head)-400, itemLine)))
	blocks := []slackBlock{slackSection(head + list)}
	for i, it := range notedItems(b.Items) {
		if i == 3 {
			break
		}
		blocks = append(blocks, slackSection("*Exposure, "+slackEscape(it.Advisory.ID)+":* "+slackEscape(defuse(exposureText(it.Advisory.Note)))))
	}
	blocks = append(blocks,
		slackContext(slackEscape(defuse("Exploitation: "+exploitSummary(b.Items)+" | Advisorydeck, data: "+bundleSources(b.Items)))),
		slackBlock{Type: "divider"},
	)
	return blocks
}

// Bundle implements Renderer: one message.
func (Slack) Bundle(b Bundle, _ time.Time) ([]Message, error) {
	raw, err := slackMessageBytes(slackEscape(defuse(bundleTitle(b))), slackBundleBlocks(b))
	if err != nil {
		return nil, err
	}
	return []Message{{Payload: raw, Items: b.Items}}, nil
}

// slackProductBlocks is one product's section: the action and one line per bundle.
func slackProductBlocks(d ProductDigest) []slackBlock {
	items := d.Items()
	lines := make([]string, 0, len(d.Bundles))
	for _, b := range d.Bundles {
		lines = append(lines, digestLine(b))
	}
	head := fmt.Sprintf("*[%s] %s*\n%s\n", levelLabel(highestOf(items).Level), slackEscape(defuse(productTitle(d.Product, d.Declared, d.Branch))), slackEscape(actionText(d.Declared, d.Branch, d.Latest)))
	return []slackBlock{
		slackSection(head + slackEscape(defuse(collapsedLines(lines, slackSectionMax-runeLen(head)-400)))),
		slackContext(slackEscape(defuse("Exploitation: " + exploitSummary(items) + " | Advisorydeck, data: " + bundleSources(items)))),
		{Type: "divider"},
	}
}

// Group implements Renderer: one message with the product's section.
func (Slack) Group(d ProductDigest, _ time.Time) ([]Message, error) {
	intro := groupIntro(d)
	raw, err := slackMessageBytes(slackEscape(defuse(intro)), append([]slackBlock{slackSection("*" + slackEscape(defuse(intro)) + "*")}, slackProductBlocks(d)...))
	if err != nil {
		return nil, err
	}
	return []Message{{Payload: raw, Items: d.Items()}}, nil
}

// Digest implements Renderer: one section per product, split so no message exceeds 50 blocks.
func (Slack) Digest(ds []ProductDigest, _ time.Time) ([]Message, error) {
	intro := digestIntro(ds)
	var out []Message
	blocks := []slackBlock{slackSection("*" + slackEscape(intro) + "*")}
	var curItems []Item
	flush := func() error {
		if len(curItems) == 0 {
			return nil
		}
		raw, err := slackMessageBytes(intro, blocks)
		if err != nil {
			return err
		}
		out = append(out, Message{Payload: raw, Items: curItems})
		blocks, curItems = nil, nil
		return nil
	}
	for _, d := range ds {
		items := d.Items()
		bs := slackProductBlocks(d)
		if len(blocks)+len(bs) > slackBlocksMax {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		blocks = append(blocks, bs...)
		curItems = append(curItems, items...)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// Summary implements Renderer: always one message, one section per product (past 48
// products the rest share one section).
func (Slack) Summary(s Summary, _ time.Time) ([]Message, error) {
	intro := summaryIntro(s)
	blocks := []slackBlock{slackSection(slackEscape(intro))}
	products := s.Products
	var rest []ProductSummary
	if len(products) > slackBlocksMax-2 {
		products, rest = products[:slackBlocksMax-2], products[slackBlocksMax-2:]
	}
	for _, p := range products {
		blocks = append(blocks, slackSection("*"+slackEscape(defuse(productTitle(p.Product, p.Declared, p.Branch)))+"*\n"+slackEscape(defuse(summaryText(p, s.MinSeverity)))))
	}
	if len(rest) > 0 {
		lines := make([]string, 0, len(rest))
		for _, p := range rest {
			lines = append(lines, fmt.Sprintf("%s: %s open", productTitle(p.Product, p.Declared, p.Branch), plural(len(p.Items), "advisory", "advisories")))
		}
		blocks = append(blocks, slackSection(slackEscape(defuse(collapsedLines(lines, slackSectionMax-50)))))
	}
	raw, err := slackMessageBytes(intro, blocks)
	if err != nil {
		return nil, err
	}
	return []Message{{Payload: raw, Items: s.Items()}}, nil
}
