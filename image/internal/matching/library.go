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
