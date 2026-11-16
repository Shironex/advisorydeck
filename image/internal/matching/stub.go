package matching

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Shironex/advisorydeck/image/internal/feed"
)

// Stub is a conservative placeholder matcher. It compares plain dotted numbers only
// (17, 17.4, 3.7.19) for the semver, pg and calver schemes and answers Unknown for
// anything else (pre-releases, dpkg, kernel strings), so it can over-notify but never
// claims "not affected" for a version it cannot read.
type Stub struct{}

// Match implements Matcher.
func (Stub) Match(d Declared, product feed.ProductInfo, a feed.Advisory) Result {
	var affected *feed.Affected
	for i := range a.Affected {
		if a.Affected[i].Product == d.Product {
			affected = &a.Affected[i]
			break
		}
	}
	if affected == nil {
		return Result{Unknown, "the advisory lists no ranges for this product, check manually"}
	}
	if len(affected.Ranges) == 0 {
		return Result{Unknown, "affected versions are unknown, check manually"}
	}
	switch product.VersionScheme {
	case "semver", "pg", "calver":
	default:
		return Result{Unknown, fmt.Sprintf("version scheme %q is not supported yet, check manually", product.VersionScheme)}
	}
	declared, ok := parseDotted(d.Version)
	if !ok {
		return Result{Unknown, fmt.Sprintf("cannot compare version %q yet, check manually", d.Version)}
	}
	for _, r := range affected.Ranges {
		intro, ok1 := parseDotted(r.Introduced)
		upper := r.Fixed
		if upper == "" {
			upper = r.LastAffected
		}
		if !ok1 {
			return Result{Unknown, fmt.Sprintf("cannot compare range %q yet, check manually", r.Introduced)}
		}
		if upper == "" {
			if compare(declared, intro) >= 0 {
				return Result{Affected, fmt.Sprintf("affected from %s, no fix released yet", r.Introduced)}
			}
			continue
		}
		up, ok2 := parseDotted(upper)
		if !ok2 {
			return Result{Unknown, fmt.Sprintf("cannot compare range %q yet, check manually", upper)}
		}
		// A branch (17) against a fix inside that branch (17.12): a floating tag is
		// affected if it was pulled before the fix release.
		if len(declared) < len(up) && isPrefix(declared, up) && compare(declared, intro) >= 0 {
			if r.Fixed != "" {
				return Result{Affected, fmt.Sprintf("branch %s is fixed in %s: affected if pulled before that release", d.Version, r.Fixed)}
			}
			return Result{Affected, fmt.Sprintf("branch %s is affected up to %s", d.Version, r.LastAffected)}
		}
		if compare(declared, intro) < 0 {
			continue
		}
		c := compare(declared, up)
		if (r.Fixed != "" && c < 0) || (r.Fixed == "" && c <= 0) {
			if r.Fixed != "" {
				return Result{Affected, fmt.Sprintf("%s is affected, fixed in %s", d.Version, r.Fixed)}
			}
			return Result{Affected, fmt.Sprintf("%s is affected up to %s", d.Version, r.LastAffected)}
		}
	}
	return Result{NotAffected, fmt.Sprintf("%s is outside every affected range", d.Version)}
}

func parseDotted(s string) ([]int, bool) {
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// compare orders dotted numbers, padding the shorter one with zeros.
func compare(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func isPrefix(prefix, full []int) bool {
	for i, n := range prefix {
		if full[i] != n {
			return false
		}
	}
	return true
}
