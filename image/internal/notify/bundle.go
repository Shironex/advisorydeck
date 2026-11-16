package notify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Shironex/advisorydeck/image/internal/feed"
)

// Change marks how an item in a bundle differs from what the channel already received.
const (
	ChangeNew     = "new"
	ChangeRevised = "revised"
)

// Bundle is what one instant message carries: the advisories of one product that the same
// release fixes for the declared version. An advisory without a known fix is a bundle of
// its own.
type Bundle struct {
	// Key is the bundle's identity: product|fix:<release>, or product|id:<advisory id>.
	Key      string
	Product  feed.ProductInfo
	Declared string
	// Branch is true when the declared version is a branch (a floating tag).
	Branch bool
	// Fix is the release that fixes the declared version, empty for a single advisory
	// without a known fix.
	Fix string
	// Latest is the newest release needed across everything open for the product: the one
	// action to take, which may be later than Fix.
	Latest string
	// Items are the advisories, most severe first.
	Items []Item
}

// BundleKey builds a bundle key: by fixing release when there is one, else by advisory.
func BundleKey(product, fix, advisoryID string) string {
	if fix != "" {
		return product + "|fix:" + fix
	}
	return product + "|id:" + advisoryID
}

// Urgent returns the first bypass rule among the items, or "".
func (b Bundle) Urgent() string {
	for _, it := range b.Items {
		if it.Urgent != "" {
			return it.Urgent
		}
	}
	return ""
}

// Highest returns the severity of the most severe item.
func (b Bundle) Highest() feed.Severity { return highestOf(b.Items) }

// ProductDigest is one product's part of a digest: its pending bundles, newest fix first.
type ProductDigest struct {
	Product  feed.ProductInfo
	Declared string
	Branch   bool
	Latest   string
	Bundles  []Bundle
}

// Items returns every item of the product's bundles.
func (d ProductDigest) Items() []Item {
	var out []Item
	for _, b := range d.Bundles {
		out = append(out, b.Items...)
	}
	return out
}

// Summary is the first message a channel gets: what is watched and what is already open,
// instead of the historical backlog one advisory at a time.
type Summary struct {
	MinSeverity string
	Mode        string
	// Backlog is true when the backlog follows as bundles (the replay flag).
	Backlog  bool
	Products []ProductSummary
}

// Items returns every item the summary covers; they count as received once it is sent.
func (s Summary) Items() []Item {
	var out []Item
	for _, p := range s.Products {
		out = append(out, p.Items...)
	}
	return out
}

// ProductSummary is one watched product in the first-start summary.
type ProductSummary struct {
	Product  feed.ProductInfo
	Declared string
	Branch   bool
	// Missing is true when the feed has no file for the product.
	Missing bool
	// Advisories is how many advisories the feed lists for the product.
	Advisories int
	// Items are the open advisories at the floor or above (or bypassing it), most severe first.
	Items []Item
	// Latest is the newest release needed; LatestDate when the newest advisory it fixes was
	// published, which is about when the fix came out.
	Latest     string
	LatestDate time.Time
	// Releases is how many distinct releases fix the items.
	Releases int
}

var severityOrder = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// SeverityRank orders severity levels; unknown levels rank 0.
func SeverityRank(level string) int { return severityOrder[level] }

func highestOf(items []Item) feed.Severity {
	var best feed.Severity
	bestRank, bestScore := -1, -1.0
	for _, it := range items {
		s := it.Advisory.Severity
		score := -1.0
		if s.Score != nil {
			score = *s.Score
		}
		if r := SeverityRank(s.Level); r > bestRank || (r == bestRank && score > bestScore) {
			best, bestRank, bestScore = s, r, score
		}
	}
	if bestRank < 0 {
		return feed.Severity{Level: "unknown", Source: "none"}
	}
	return best
}

// levelCounts says how many items have each level, most severe first: "1 critical, 3 high".
func levelCounts(items []Item) string {
	counts := map[string]int{}
	for _, it := range items {
		l := it.Advisory.Severity.Level
		if SeverityRank(l) == 0 {
			l = "unknown"
		}
		counts[l]++
	}
	var parts []string
	for _, l := range []string{"critical", "high", "medium", "low", "unknown"} {
		if counts[l] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[l], l))
		}
	}
	return strings.Join(parts, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// actionText is the one thing to do for a product, shared by bundles, digests and summaries.
func actionText(declared string, branch bool, latest string) string {
	switch {
	case latest == "":
		return "No fixed release is known for your version; read the advisory and check manually."
	case branch:
		return fmt.Sprintf("Make sure you run %s or later. On the floating %s tag, pull the image again and recreate the container.", latest, declared)
	default:
		return fmt.Sprintf("Upgrade from %s to %s or later.", declared, latest)
	}
}

// bundleTitle is the one-line title of a bundle.
func bundleTitle(b Bundle) string {
	if len(b.Items) == 1 {
		return headline(b.Items[0])
	}
	badge := ""
	if exploited(b.Items) {
		badge = " [EXPLOITED]"
	}
	return fmt.Sprintf("[%s]%s %s %s fixes %d advisories for %s", levelLabel(b.Highest().Level), badge, b.Product.Name, b.Fix, len(b.Items), b.Declared)
}

// bundleLead is the opening of a multi-item bundle: the action and the severity breakdown.
func bundleLead(b Bundle) string {
	lead := actionText(b.Declared, b.Branch, b.Latest)
	if b.Latest != "" && b.Fix != "" && b.Latest != b.Fix {
		lead = fmt.Sprintf("%s fixes these; %s is the newest release you need. %s", b.Fix, b.Latest, lead)
	}
	return lead + "\nSeverity: " + levelCounts(b.Items) + ", highest " + severityText(b.Highest()) + "."
}

func exploited(items []Item) bool {
	for _, it := range items {
		if it.Advisory.KEV.Listed {
			return true
		}
	}
	return false
}

// itemLine is one advisory in a collapsed list.
func itemLine(it Item) string {
	var b strings.Builder
	b.WriteString(it.Advisory.ID)
	b.WriteString(" " + levelLabel(it.Advisory.Severity.Level))
	if s := it.Advisory.Severity.Score; s != nil {
		fmt.Fprintf(&b, " %.1f", *s)
	}
	switch {
	case it.Advisory.KEV.Listed:
		b.WriteString(" [KEV]")
	case it.Urgent == UrgentEPSS:
		b.WriteString(" [EPSS]")
	}
	if it.Change != "" {
		b.WriteString(" (" + it.Change + ")")
	}
	b.WriteString(": " + it.Advisory.Title)
	return b.String()
}

// collapsedList joins item lines until max runes, then says how many were left out.
func collapsedList(items []Item, limit int, line func(Item) string) string {
	lines := make([]string, 0, len(items))
	for _, it := range items {
		lines = append(lines, line(it))
	}
	return collapsedLines(lines, limit)
}

// collapsedLines joins lines as a list until limit runes, then says how many were left out.
func collapsedLines(lines []string, limit int) string {
	var b strings.Builder
	for i, raw := range lines {
		l := "- " + truncate(raw, 160) + "\n"
		rest := len(lines) - i
		more := ""
		if rest > 1 {
			more = fmt.Sprintf("and %d more", rest-1)
		}
		if runeLen(b.String())+runeLen(l)+runeLen(more)+1 > limit {
			fmt.Fprintf(&b, "and %d more", rest)
			return b.String()
		}
		b.WriteString(l)
	}
	return strings.TrimRight(b.String(), "\n")
}

// exploitSummary describes the exploitation signals of a group of items.
func exploitSummary(items []Item) string {
	var listed, likely []string
	unchecked := 0
	for _, it := range items {
		switch {
		case it.Advisory.KEV.Listed:
			listed = append(listed, it.Advisory.ID)
		case it.Urgent == UrgentEPSS:
			likely = append(likely, it.Advisory.ID)
		}
		if it.Advisory.KEV.State() == feed.KEVNotChecked {
			unchecked++
		}
	}
	var parts []string
	if len(listed) > 0 {
		parts = append(parts, "in CISA KEV (exploited in the wild): "+strings.Join(listed, ", "))
	}
	if len(likely) > 0 {
		parts = append(parts, "EPSS says likely to be exploited: "+strings.Join(likely, ", "))
	}
	switch {
	case unchecked == len(items):
		parts = append(parts, "CISA KEV not checked")
	case unchecked > 0:
		parts = append(parts, fmt.Sprintf("CISA KEV not checked for %d", unchecked))
	case len(listed) == 0:
		parts = append(parts, "none in CISA KEV")
	}
	return strings.Join(parts, "; ")
}

// notedItems returns the items that carry a reviewed note.
func notedItems(items []Item) []Item {
	var out []Item
	for _, it := range items {
		if it.Advisory.Note != nil {
			out = append(out, it)
		}
	}
	return out
}

// bundleSources lists the data sources of all items, without repeats.
func bundleSources(items []Item) string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		for _, s := range strings.Split(sourceNames(it), ", ") {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// summaryText is one product's paragraph in the first-start summary, without markup.
func summaryText(p ProductSummary, floor string) string {
	if p.Missing {
		return fmt.Sprintf("The feed has no file for %s yet, so nothing can be matched.", p.Product.Slug)
	}
	if len(p.Items) == 0 {
		return fmt.Sprintf("Nothing open at %s or above among the %s in the feed.", floor, plural(p.Advisories, "advisory", "advisories"))
	}
	var b strings.Builder
	who := p.Declared
	if p.Branch {
		who = "Branch " + p.Declared
	}
	releases := ""
	if p.Releases > 0 {
		releases = ", fixed across " + plural(p.Releases, "release", "releases")
	}
	fmt.Fprintf(&b, "%s has %s at %s or above%s (%s).", who, plural(len(p.Items), "open advisory", "open advisories"), floor, releases, levelCounts(p.Items))
	if p.Latest != "" {
		b.WriteString(" " + actionText(p.Declared, p.Branch, p.Latest))
		if p.Branch && !p.LatestDate.IsZero() {
			fmt.Fprintf(&b, " That applies if you last pulled before %s.", p.LatestDate.UTC().Format("2006-01-02"))
		}
	}
	var open, urgent []string
	for _, it := range p.Items {
		if it.FixedIn == "" {
			open = append(open, it.Advisory.ID)
		}
		if it.Urgent != "" {
			urgent = append(urgent, it.Advisory.ID+" ("+urgentLabel(it.Urgent)+")")
		}
	}
	if len(open) > 0 {
		fmt.Fprintf(&b, "\n%s without a fix for your version or with unknown versions, check manually: %s.", plural(len(open), "advisory", "advisories"), listSome(open, 6))
	}
	if len(urgent) > 0 {
		fmt.Fprintf(&b, "\nNeeds attention now: %s.", listSome(urgent, 6))
	}
	return b.String()
}

func urgentLabel(u string) string {
	switch u {
	case UrgentKEV:
		return "in CISA KEV"
	case UrgentEPSS:
		return "EPSS likely exploited"
	case UrgentActionRequired:
		return "exposed on a default setup"
	}
	return u
}

func listSome(xs []string, n int) string {
	if len(xs) <= n {
		return strings.Join(xs, ", ")
	}
	return strings.Join(xs[:n], ", ") + fmt.Sprintf(" and %d more", len(xs)-n)
}

func summaryIntro(s Summary) string {
	next := "From now on it posts only new and revised advisories"
	if s.Backlog {
		next = "The open advisories follow, one message per release, as asked; after that it posts only new and revised ones"
	}
	return fmt.Sprintf("Advisorydeck is now watching %s for this channel. %s at %s or above (mode: %s). What is already open is summarized here instead of posted one by one.",
		plural(len(s.Products), "product", "products"), next, s.MinSeverity, s.Mode)
}

func digestIntro(ds []ProductDigest) string {
	items, bundles := 0, 0
	for _, d := range ds {
		bundles += len(d.Bundles)
		items += len(d.Items())
	}
	return fmt.Sprintf("Advisorydeck daily digest: %s in %s for %s", plural(items, "advisory", "advisories"), plural(bundles, "message", "messages"), plural(len(ds), "product", "products"))
}

func groupIntro(d ProductDigest) string {
	return fmt.Sprintf("Advisorydeck: %s fix %s for %s %s", plural(len(d.Bundles), "release", "releases"), plural(len(d.Items()), "advisory", "advisories"), d.Product.Name, d.Declared)
}

func productTitle(p feed.ProductInfo, declared string, branch bool) string {
	if branch {
		return fmt.Sprintf("%s %s (branch)", p.Name, declared)
	}
	return p.Name + " " + declared
}

// digestLine is one bundle in a product's digest entry.
func digestLine(b Bundle) string {
	if len(b.Items) == 1 {
		it := b.Items[0]
		fix := b.Fix
		if fix == "" {
			fix = "no known fix"
		}
		return fix + ": " + itemLine(it)
	}
	ids := make([]string, 0, len(b.Items))
	for _, it := range b.Items {
		ids = append(ids, it.Advisory.ID)
	}
	return fmt.Sprintf("%s fixes %d (%s, highest %s): %s", b.Fix, len(b.Items), levelCounts(b.Items), levelLabel(b.Highest().Level), listSome(ids, 8))
}

func runeLen(s string) int { return len([]rune(s)) }
