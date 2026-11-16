package match

import (
	"fmt"

	"github.com/Shironex/advisorydeck/image/internal/feed"
)

// Outcome is the answer to "does this advisory hit what I run". The zero value is
// OutcomeUnknown, so a Result nobody filled in never reads as safe.
type Outcome int

// The three outcomes.
const (
	OutcomeUnknown Outcome = iota
	OutcomeAffected
	OutcomeNotAffected
)

// String returns unknown, affected or not-affected (the names used by fixtures/match).
func (o Outcome) String() string {
	switch o {
	case OutcomeAffected:
		return "affected"
	case OutcomeNotAffected:
		return "not-affected"
	default:
		return "unknown"
	}
}

// Reason says why a Result has its outcome. The values are stable codes used by
// fixtures/match; show Result.Detail to people.
type Reason string

// Reasons for each outcome.
const (
	// ReasonInRange: an exact version is inside a range. Outcome affected.
	ReasonInRange Reason = "in-range"
	// ReasonBranchInRange: the installed value is a branch (a floating tag such as
	// postgres:17) and part or all of that branch is inside a range. Outcome affected: the
	// container is affected if it was pulled before the fixed release.
	ReasonBranchInRange Reason = "branch-in-range"
	// ReasonOutsideRanges: every range was read and none covers the version or any release
	// of the branch. Outcome not affected; the only way to get it.
	ReasonOutsideRanges Reason = "outside-ranges"
	// ReasonNoRanges: the advisory lists the product without ranges. Outcome unknown.
	ReasonNoRanges Reason = "no-ranges"
	// ReasonProductNotListed: the advisory does not list the product at all. Outcome unknown.
	ReasonProductNotListed Reason = "product-not-listed"
	// ReasonBadVersion: the installed version cannot be read in the scheme. Outcome unknown.
	ReasonBadVersion Reason = "unparseable-version"
	// ReasonBadRange: a range bound cannot be read and no other range matched. Outcome unknown.
	ReasonBadRange Reason = "unparseable-range"
	// ReasonFloatingTag: an image tag such as latest names no version. Outcome unknown.
	ReasonFloatingTag Reason = "floating-tag"
	// ReasonNotComparable: the scheme cannot order versions (opaque) and no bound equals
	// the installed version. Outcome unknown.
	ReasonNotComparable Reason = "not-comparable"
)

// Result is the answer for one installed version and one advisory.
type Result struct {
	Outcome Outcome
	Reason  Reason
	// Detail is a one-line explanation for people, without markup.
	Detail string
	// Range is the range that decided an affected outcome; nil otherwise.
	Range *feed.Range
	// FixedIn is the fixed version of Range, empty when the range has no fix
	// (last_affected only, or still unfixed).
	FixedIn string
	// Branch is true when the installed value was a branch, so the answer covers every
	// release of it rather than one version.
	Branch bool
}

// Check evaluates an advisory for the product slug at the installed branch or
// exact version (the version field of the image config).
func Check(scheme Scheme, installed, slug string, adv feed.Advisory) Result {
	v, err := Parse(scheme, installed)
	if err != nil {
		return unknown(ReasonBadVersion, err.Error())
	}
	return CheckVersion(v, slug, adv)
}

// CheckVersion is Check for an already parsed version.
//
// Every affected entry for the slug counts. An entry with an empty range list means its
// affected versions are unknown, so when no known range matches the result is unknown,
// never not affected.
func CheckVersion(v Version, slug string, adv feed.Advisory) Result {
	var (
		listed  bool
		unknown bool
		ranges  []feed.Range
	)
	for _, a := range adv.Affected {
		if a.Product != slug {
			continue
		}
		listed = true
		if len(a.Ranges) == 0 {
			unknown = true
		}
		ranges = append(ranges, a.Ranges...)
	}
	if !listed {
		return Result{
			Reason: ReasonProductNotListed,
			Detail: fmt.Sprintf("%s does not list %s; check manually", adv.ID, slug),
			Branch: v.IsBranch(),
		}
	}
	r := EvaluateVersion(v, ranges)
	if unknown && r.Outcome != OutcomeAffected {
		return Result{
			Reason: ReasonNoRanges,
			Detail: "the advisory does not say which versions are affected; check manually",
			Branch: v.IsBranch(),
		}
	}
	return r
}

// Evaluate parses installed in the scheme and evaluates it against ranges.
func Evaluate(scheme Scheme, installed string, ranges []feed.Range) Result {
	v, err := Parse(scheme, installed)
	if err != nil {
		return unknown(ReasonBadVersion, err.Error())
	}
	return EvaluateVersion(v, ranges)
}

// EvaluateVersion evaluates a parsed branch or exact version against an advisory's ranges
// for one product.
//
// An empty list is unknown. Otherwise the version is affected when any range covers it
// (for a branch: any release of the branch), not affected only when every range was read
// and none covers it, and unknown when a range could not be read and none matched.
func EvaluateVersion(v Version, ranges []feed.Range) Result {
	if len(ranges) == 0 {
		return Result{
			Reason: ReasonNoRanges,
			Detail: "the advisory does not say which versions are affected; check manually",
			Branch: v.IsBranch(),
		}
	}
	if !v.scheme.comparable() {
		return evaluateOpaque(v, ranges)
	}
	var (
		badRange error
		hit      *feed.Range
		hitIn    bool     // the hit range's fix lies inside the installed branch
		hitFix   *Version // the hit range's parsed fix
	)
	for i := range ranges {
		b, err := readBounds(v.scheme, ranges[i])
		if err != nil {
			if badRange == nil {
				badRange = err
			}
			continue
		}
		if !v.IsBranch() {
			if b.contains(v) {
				return affected(v, &ranges[i])
			}
			continue
		}
		if !b.intersectsBranch(v) {
			continue
		}
		// Prefer a range whose fix ships inside the branch, and among those the highest
		// fix: a floating tag runs the newest release of the branch, so that is the
		// release to pull (redis 8 fixed in 8.0.4 and 8.2.2 means pull 8.2.2).
		in := b.fixed != nil && b.fixed.depth == 0 && Compare(*b.fixed, v.branchLow()) >= 0 &&
			Compare(*b.fixed, v.branchHigh()) < 0
		switch {
		case hit == nil, in && !hitIn:
			hit, hitIn, hitFix = &ranges[i], in, b.fixed
		case in && hitIn && Compare(*b.fixed, *hitFix) > 0:
			hit, hitFix = &ranges[i], b.fixed
		}
	}
	if hit != nil {
		return affected(v, hit)
	}
	if badRange != nil {
		return unknown(ReasonBadRange, badRange.Error())
	}
	return Result{
		Outcome: OutcomeNotAffected,
		Reason:  ReasonOutsideRanges,
		Detail:  notAffectedDetail(v),
		Branch:  v.IsBranch(),
	}
}

func unknown(reason Reason, detail string) Result {
	return Result{Reason: reason, Detail: detail + "; check manually"}
}

func affected(v Version, r *feed.Range) Result {
	res := Result{Outcome: OutcomeAffected, Reason: ReasonInRange, Range: r, FixedIn: r.Fixed, Branch: v.IsBranch()}
	switch {
	case v.IsBranch() && r.Fixed != "":
		res.Reason = ReasonBranchInRange
		res.Detail = fmt.Sprintf("branch %s is affected before %s; if you run a floating tag, pull again and recreate the container, or upgrade to %s or later", v, r.Fixed, r.Fixed)
	case v.IsBranch():
		res.Reason = ReasonBranchInRange
		res.Detail = fmt.Sprintf("branch %s is affected and the advisory names no fixed release", v)
	case r.Fixed != "":
		res.Detail = fmt.Sprintf("%s is affected; fixed in %s", v, r.Fixed)
	default:
		res.Detail = fmt.Sprintf("%s is affected and the advisory names no fixed release", v)
	}
	return res
}

func notAffectedDetail(v Version) string {
	if v.IsBranch() {
		return fmt.Sprintf("no release of branch %s is in the affected ranges", v)
	}
	return fmt.Sprintf("%s is outside the affected ranges", v)
}

// bounds is a range with its versions parsed. low nil means from the first version;
// fixed and last nil mean no upper bound.
type bounds struct {
	low   *Version
	fixed *Version
	last  *Version
}

func readBounds(scheme Scheme, r feed.Range) (bounds, error) {
	var b bounds
	if r.Fixed != "" && r.LastAffected != "" {
		return b, fmt.Errorf("range from %q has both fixed and last_affected", r.Introduced)
	}
	if r.Introduced != "0" {
		v, err := Parse(scheme, r.Introduced)
		if err != nil {
			return b, fmt.Errorf("introduced: %w", err)
		}
		b.low = &v
	}
	if r.Fixed != "" {
		v, err := Parse(scheme, r.Fixed)
		if err != nil {
			return b, fmt.Errorf("fixed: %w", err)
		}
		b.fixed = &v
	}
	if r.LastAffected != "" {
		v, err := Parse(scheme, r.LastAffected)
		if err != nil {
			return b, fmt.Errorf("last_affected: %w", err)
		}
		b.last = &v
	}
	return b, nil
}

// below reports whether x sits under the range's upper bound.
func (b bounds) below(x Version) bool {
	switch {
	case b.fixed != nil:
		// fixed is exclusive; a branch written as fixed (18) means its first version.
		return Compare(x, b.fixed.rangeLow()) < 0
	case b.last != nil && b.last.IsBranch():
		// last_affected 17 covers every release of branch 17.
		return Compare(x, b.last.branchHigh()) < 0
	case b.last != nil:
		return Compare(x, *b.last) <= 0
	default:
		return true
	}
}

// contains reports whether an exact version is inside the range.
func (b bounds) contains(x Version) bool {
	if b.low != nil && Compare(x, b.low.rangeLow()) < 0 {
		return false
	}
	return b.below(x)
}

// intersectsBranch reports whether any release of the branch br is inside the range.
// Floating tags never point at prereleases, so a range that only spans prereleases
// (3.8.0-rc.1 to 3.8.0-rc.2) does not hit branch 3. The check takes the first release
// that is both in the branch and at or above the range start, and tests it against the
// upper bound.
func (b bounds) intersectsBranch(br Version) bool {
	start, hi := br.branchLow(), br.branchHigh()
	if b.low != nil {
		if l := b.low.rangeLow().releaseCeil(); Compare(l, start) > 0 {
			start = l
		}
	}
	if Compare(start, hi) >= 0 {
		return false
	}
	return b.below(start)
}

// evaluateOpaque handles schemes without an order: only equality with a bound counts.
func evaluateOpaque(v Version, ranges []feed.Range) Result {
	for i := range ranges {
		r := &ranges[i]
		if r.Introduced == v.raw || r.LastAffected == v.raw {
			return affected(v, r)
		}
	}
	return unknown(ReasonNotComparable, fmt.Sprintf("versions of this product cannot be ordered and %s is not named in the advisory", v))
}
