package matching

import (
	"github.com/Shironex/advisorydeck/image/internal/feed"
	"github.com/Shironex/advisorydeck/image/internal/match"
)

// Library is the production Matcher: it asks internal/match about the declared branch or
// exact version in the product's version scheme. Its unknown answers (no ranges, an
// unreadable version, a scheme without order) stay unknown, never not affected.
type Library struct{}

// Match implements Matcher.
func (Library) Match(d Declared, product feed.ProductInfo, a feed.Advisory) Result {
	r := match.Check(match.Scheme(product.VersionScheme), d.Version, d.Product, a)
	return Result{Verdict: verdictOf(r.Outcome), Reason: r.Detail, Code: string(r.Reason), FixedIn: r.FixedIn, Branch: r.Branch}
}

func verdictOf(o match.Outcome) Verdict {
	switch o {
	case match.OutcomeAffected:
		return Affected
	case match.OutcomeNotAffected:
		return NotAffected
	default:
		return Unknown
	}
}

// CompareVersions orders two versions of one product's scheme: negative when a is before b,
// zero when equal, positive when after. A version the scheme cannot read sorts before every
// readable one, and two unreadable ones compare as text, so the order is always stable.
func CompareVersions(scheme, a, b string) int {
	va, errA := match.Parse(match.Scheme(scheme), a)
	vb, errB := match.Parse(match.Scheme(scheme), b)
	switch {
	case errA == nil && errB == nil:
		if c := match.Compare(va, vb); c != 0 {
			return c
		}
	case errA == nil:
		return 1
	case errB == nil:
		return -1
	}
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
