// Package matching defines the seam between the daemon and the version matcher.
//
// The daemon only needs one question answered: given what the user declared and one
// advisory, is the user affected, not affected, or is it unknown? The real matcher
// (version schemes, per-branch ranges) lives in internal/match; Stub is a deliberately
// small stand-in that answers conservatively until that package is wired in.
package matching

import "github.com/Shironex/advisorydeck/image/internal/feed"

// Verdict is the matcher's answer.
type Verdict string

// Verdicts. Unknown is never reported as "not affected": the daemon notifies it with a
// "check manually" label.
const (
	Affected    Verdict = "affected"
	NotAffected Verdict = "not-affected"
	Unknown     Verdict = "unknown"
)

// Declared is what the user says they run, from the config file.
type Declared struct {
	// Product is the catalog slug.
	Product string
	// Version is a branch (17) or an exact version (17.4).
	Version string
	// Image is the image reference, when known. The v1 config has no image field yet, so
	// it is empty today; it is part of the seam so the matcher can use tag grammar later.
	Image string
}

// Result is a verdict plus a short human reason, shown in notifications and logs.
type Result struct {
	Verdict Verdict
	Reason  string
}

// Matcher answers whether one advisory affects what the user declared. product carries
// the version scheme and branches from the product file.
type Matcher interface {
	Match(declared Declared, product feed.ProductInfo, advisory feed.Advisory) Result
}

// Func adapts a plain function to Matcher, so another package's matcher can be wired in
// with one line.
type Func func(declared Declared, product feed.ProductInfo, advisory feed.Advisory) Result

// Match implements Matcher.
func (f Func) Match(declared Declared, product feed.ProductInfo, advisory feed.Advisory) Result {
	return f(declared, product, advisory)
}
