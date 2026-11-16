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
	fmt.Fprintf(&b, "*Fixed in:* %s\n", slackEscape(strings.Join(fixedIn(it), ", ")))
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

// Render implements Renderer. Digests are split so no message exceeds 50 blocks.
func (Slack) Render(items []Item, kind Kind, _ time.Time) ([]Message, error) {
	var out []Message
	var blocks []slackBlock
	var curItems []Item
	flush := func() error {
		if len(curItems) == 0 {
			return nil
		}
		text := slackEscape(defuse(headline(curItems[0])))
		if kind == Digest {
			text = fmt.Sprintf("Advisorydeck daily digest: %d advisories for what you run", len(items))
		}
		raw, err := json.Marshal(slackMessage{Text: truncate(text, slackTextMax), Blocks: blocks})
		if err != nil {
			return err
		}
		out = append(out, Message{Payload: raw, Items: curItems})
		blocks, curItems = nil, nil
		return nil
	}
	for _, it := range items {
		bs := slackBlocksFor(it, kind)
		if len(blocks)+len(bs) > slackBlocksMax {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		blocks = append(blocks, bs...)
		curItems = append(curItems, it)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}
