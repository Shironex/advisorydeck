package notify

import (
	"encoding/json"
	"fmt"
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

// Render implements Renderer. Every message stays within 10 embeds and 6000 characters.
func (Discord) Render(items []Item, kind Kind, _ time.Time) ([]Message, error) {
	var out []Message
	content := ""
	if kind == Digest {
		content = truncate(fmt.Sprintf("Advisorydeck daily digest: %d advisories for what you run", len(items)), discordContentMax)
	}
	cur := discordMessage{Content: content, Username: "Advisorydeck", AllowedMentions: allowedMentions{Parse: []string{}}}
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
		cur = discordMessage{Username: "Advisorydeck", AllowedMentions: allowedMentions{Parse: []string{}}}
		curItems, total = nil, 0
		return nil
	}
	for _, it := range items {
		e := discordEmbedFor(it, kind)
		if len(cur.Embeds) == discordEmbedsMax || total+e.size() > discordTotalMax {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		cur.Embeds = append(cur.Embeds, e)
		curItems = append(curItems, it)
		total += e.size()
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}
