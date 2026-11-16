// Package notify renders matched advisories for Discord, Slack and generic JSON webhooks
// and delivers them: one queue per webhook, rate limits and retry_after honoured,
// exponential backoff on server errors, and a webhook that answers 401/403/404/410
// disabled instead of retried.
//
// Webhook URLs are secrets: they are never logged, and errors that would carry them are
// stripped of the URL first.
package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Shironex/advisorydeck/image/internal/feed"
	"github.com/Shironex/advisorydeck/image/internal/matching"
)

// Kind says whether a message is an instant notification or part of the daily digest.
type Kind string

// Message kinds.
const (
	Instant Kind = "instant"
	Digest  Kind = "digest"
)

// Urgent reasons: the bypass rules that post instantly whatever the severity floor.
const (
	UrgentKEV            = "kev"
	UrgentEPSS           = "epss"
	UrgentActionRequired = "action-required"
)

// Item is one advisory matched against one declared product.
type Item struct {
	Key      string // advisory id|product slug, the dedupe key
	Advisory feed.Advisory
	Product  feed.ProductInfo
	Declared string
	Verdict  matching.Verdict
	Reason   string
	// FixedIn is the release that fixes the declared version (for a branch, the highest
	// fix inside it: the one to pull), empty when unknown or unfixed.
	FixedIn string
	// Branch is true when Declared is a branch (a floating tag).
	Branch bool
	Urgent string // "", UrgentKEV, UrgentEPSS or UrgentActionRequired
	// Change is "", ChangeNew or ChangeRevised: how the item differs from what the channel
	// received before. Set per channel, only inside bundles that mix old and new.
	Change string
}

// Key builds the dedupe key of an advisory for a product.
func Key(advisoryID, product string) string { return advisoryID + "|" + product }

// Message is one payload ready to post, with the items it carries.
type Message struct {
	Payload []byte
	Items   []Item
}

// Renderer turns bundles, digests and summaries into payloads for one channel type, always
// within the target's limits. A bundle and a summary are one message each; a long digest is
// split over several. A group is one message.
type Renderer interface {
	Bundle(b Bundle, now time.Time) ([]Message, error)
	// Group is one instant message for several bundles of one product that are due at the
	// same time (a vendor publishing a batch fixed in different releases).
	Group(d ProductDigest, now time.Time) ([]Message, error)
	Digest(products []ProductDigest, now time.Time) ([]Message, error)
	Summary(s Summary, now time.Time) ([]Message, error)
}

// RendererFor returns the renderer of a channel type.
func RendererFor(channelType string) (Renderer, error) {
	switch channelType {
	case "discord":
		return Discord{}, nil
	case "slack":
		return Slack{}, nil
	case "webhook":
		return Webhook{}, nil
	}
	return nil, fmt.Errorf("unknown channel type %q", channelType)
}

// ValidateURL checks a webhook URL taken from the environment. Discord and Slack must use
// https; a generic webhook may use http for a receiver on the local network. The error
// never repeats the URL.
func ValidateURL(channelType, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("not a URL")
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && channelType == "webhook":
		return nil
	}
	return fmt.Errorf("must start with https://")
}

// Fingerprint identifies a URL without revealing it: a truncated sha256.
func Fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:6])
}

// severity ranks for display.
var severityLabel = map[string]string{"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}

func levelLabel(level string) string {
	if l, ok := severityLabel[level]; ok {
		return l
	}
	return "UNKNOWN"
}

// headline is the one-line title shared by every channel type.
func headline(it Item) string {
	badge := ""
	if it.Advisory.KEV.Listed {
		badge = " [EXPLOITED]"
	}
	return fmt.Sprintf("[%s]%s %s%s %s: %s", levelLabel(it.Advisory.Severity.Level), badge, it.Product.Name, upstreamBadge(it.Product), it.Declared, it.Advisory.Title)
}

// upstreamBadge marks a product whose upstream no longer ships fixes, in every title.
func upstreamBadge(p feed.ProductInfo) string {
	switch {
	case p.Upstream == nil:
		return ""
	case p.Upstream.Status == feed.UpstreamArchived:
		return " [UPSTREAM ARCHIVED]"
	default:
		return " [UPSTREAM " + strings.ToUpper(p.Upstream.Status) + "]"
	}
}

// upstreamText is the warning for a product whose upstream no longer ships fixes, empty for a
// maintained one. Every message about such a product carries it.
func upstreamText(p feed.ProductInfo) string {
	u := p.Upstream
	if u == nil {
		return ""
	}
	var b strings.Builder
	if u.Status == feed.UpstreamArchived {
		b.WriteString("Upstream archived " + p.Name)
		if u.Since != "" {
			b.WriteString(" on " + u.Since)
		}
		b.WriteString(", so no further fixes are expected: plan a move to a maintained alternative.")
	} else {
		fmt.Fprintf(&b, "Upstream status of %s: %s.", p.Name, u.Status)
		if u.Since != "" {
			b.WriteString(" Since " + u.Since + ".")
		}
	}
	if note := strings.TrimSpace(u.Note); note != "" {
		b.WriteString(" " + note)
	}
	return b.String()
}

// withUpstream puts the upstream warning, if any, on its own line before text.
func withUpstream(p feed.ProductInfo, text string) string {
	if w := upstreamText(p); w != "" {
		return w + "\n" + text
	}
	return text
}

// fixText says which release fixes the user's version, then every fix of the advisory.
func fixText(it Item) string {
	all := strings.Join(fixedIn(it), ", ")
	if it.FixedIn == "" {
		return all
	}
	return it.FixedIn + " for your version (all fixes: " + all + ")"
}

// fixedIn lists the fix versions for the item's product, or says why there are none.
func fixedIn(it Item) []string {
	var out []string
	open := false
	for _, a := range it.Advisory.Affected {
		if a.Product != it.Product.Slug {
			continue
		}
		for _, r := range a.Ranges {
			if r.Fixed != "" {
				out = append(out, r.Fixed)
			} else if r.LastAffected == "" {
				open = true
			}
		}
	}
	if open {
		out = append(out, "no fix released yet")
	}
	if len(out) == 0 {
		out = append(out, "unknown, check the advisory")
	}
	return out
}

// link returns the advisory link to show: the first https advisory reference, else the
// first https reference, else the first https source.
func link(a feed.Advisory) string {
	for _, r := range a.References {
		if r.Type == "advisory" && isHTTPS(r.URL) {
			return r.URL
		}
	}
	for _, r := range a.References {
		if isHTTPS(r.URL) {
			return r.URL
		}
	}
	for _, s := range a.Sources {
		if isHTTPS(s.URL) {
			return s.URL
		}
	}
	return ""
}

func isHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func ids(a feed.Advisory) string {
	if len(a.Aliases) == 0 {
		return a.ID
	}
	return a.ID + " (" + strings.Join(a.Aliases, ", ") + ")"
}

func severityText(s feed.Severity) string {
	if s.Score == nil {
		return levelLabel(s.Level) + ", no CVSS score"
	}
	return fmt.Sprintf("%s %.1f (%s)", levelLabel(s.Level), *s.Score, s.Source)
}

func exploitText(a feed.Advisory) string {
	parts := []string{}
	switch a.KEV.State() {
	case feed.KEVListed:
		parts = append(parts, "in CISA KEV (exploited in the wild)")
	case feed.KEVNotListed:
		parts = append(parts, "not in CISA KEV")
	default:
		// Never "not in KEV": the catalog was not read for this advisory.
		parts = append(parts, "CISA KEV not checked")
	}
	if a.EPSS != nil {
		parts = append(parts, fmt.Sprintf("EPSS %.1f%% (percentile %.0f)", a.EPSS.Score*100, a.EPSS.Percentile*100))
	}
	return strings.Join(parts, ", ")
}

var exposureLabel = map[string]string{
	"default-exposed": "Exposed on a default setup",
	"conditional":     "Exposed only in some setups",
	"not-default":     "Not exposed on a default setup",
	"unknown":         "Exposure unknown",
}

// exposureText always carries the assumptions next to the label.
func exposureText(n *feed.Note) string {
	label, ok := exposureLabel[n.Exposure]
	if !ok {
		label = exposureLabel["unknown"]
	}
	if len(n.Assumptions) == 0 {
		return label
	}
	return label + ", assuming:\n- " + strings.Join(n.Assumptions, "\n- ")
}

func actionLines(n *feed.Note, codeFence bool) string {
	var b strings.Builder
	for i, a := range n.Actions {
		fmt.Fprintf(&b, "%d. %s", i+1, a.Kind)
		if a.Text != "" {
			b.WriteString(": " + a.Text)
		}
		b.WriteString("\n")
		if a.Code != "" {
			if codeFence {
				b.WriteString("```\n" + strings.TrimRight(a.Code, "\n") + "\n```\n")
			} else {
				b.WriteString(strings.TrimRight(a.Code, "\n") + "\n")
			}
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// truncate cuts s to at most n runes, ending in "..." when cut.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n <= 3 {
		return string([]rune(s)[:n])
	}
	return string([]rune(s)[:n-3]) + "..."
}

// defuse breaks mass mentions in third-party text. allowed_mentions already stops pings
// on Discord; this keeps the text from looking like one anywhere.
func defuse(s string) string {
	r := strings.NewReplacer("@everyone", "@\u200beveryone", "@here", "@\u200bhere", "<!channel>", "channel", "<!here>", "here", "<!everyone>", "everyone")
	return r.Replace(s)
}
