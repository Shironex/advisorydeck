// Package match decides whether an installed version of a product is hit by an advisory.
//
// It knows the version schemes of schemas/v1 (semver, pg, calver, dpkg, kernel, opaque),
// evaluates an advisory's per-branch ranges against a branch or an exact version, and
// resolves image tags to versions with the catalog's tag patterns. Every answer is one of
// three outcomes: affected, not affected, or unknown with a reason. The zero Result is
// unknown, an advisory without ranges is unknown, and a version that cannot be read is
// unknown: the package never answers "not affected" by default.
//
// The package is pure: no I/O, no network, no clock. The test vectors live in
// fixtures/match so a TypeScript port can run the same cases.
package match

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Scheme names how versions of a product compare (defs.schema.json#/$defs/versionScheme).
type Scheme string

// The version schemes of schemas/v1.
const (
	// SchemeSemver is semantic versioning with lenient input: a leading v, one to three
	// numeric components, leading zeros (Docker's 19.03.15) and build metadata are accepted.
	// One or two components without a prerelease name a branch (3.2, 8).
	SchemeSemver Scheme = "semver"
	// SchemePG is PostgreSQL's scheme: major.minor since 10 (17 is a branch, 17.4 a release),
	// major.minor.patch before (9.6 is a branch, 9.6.24 a release), with prereleases written
	// straight after the version (18beta1, 9.6rc1).
	SchemePG Scheme = "pg"
	// SchemeCalver is dotted calendar numbers (2024.10.1). Every version is exact.
	SchemeCalver Scheme = "calver"
	// SchemeDpkg is a Debian package version (epoch:upstream-revision), compared with the
	// dpkg algorithm, including ~ sorting before everything.
	SchemeDpkg Scheme = "dpkg"
	// SchemeKernel is an upstream Linux kernel version (6.1.115, 6.12-rc3). Distro kernel
	// strings such as 6.8.0-45-generic are rejected: they need a distro notice, not a range.
	SchemeKernel Scheme = "kernel"
	// SchemeOpaque supports equality only.
	SchemeOpaque Scheme = "opaque"
)

// maxVersionLen mirrors maxLength of defs.schema.json#/$defs/version.
const maxVersionLen = 64

// Errors returned by Parse, wrapped with the offending input.
var (
	ErrUnknownScheme = errors.New("unknown version scheme")
	ErrInvalid       = errors.New("invalid version")
)

// Version is a parsed version or branch. Build one with Parse; the zero Version is invalid.
type Version struct {
	scheme Scheme
	raw    string
	// nums are the numeric release components, padded to the scheme's length.
	nums []uint64
	// pre holds prerelease identifiers; nil for a release.
	pre []string
	// depth is the number of significant components when the version names a branch
	// (17 in pg, 3.2 in semver), and 0 for an exact version.
	depth int
	// floor marks a synthetic bound just below every version (prereleases included) that
	// shares nums. Only range evaluation creates it.
	floor bool
	deb   debVersion
}

// Parse reads s in the given scheme.
func Parse(scheme Scheme, s string) (Version, error) {
	if len(s) == 0 || len(s) > maxVersionLen {
		return Version{}, fmt.Errorf("%w %q: length must be 1 to %d", ErrInvalid, s, maxVersionLen)
	}
	var (
		v   Version
		err error
	)
	switch scheme {
	case SchemeSemver:
		v, err = parseSemver(s)
	case SchemePG:
		v, err = parsePG(s)
	case SchemeCalver:
		v, err = parseCalver(s)
	case SchemeKernel:
		v, err = parseKernel(s)
	case SchemeDpkg:
		v, err = parseDpkg(s)
	case SchemeOpaque:
		v, err = parseOpaque(s)
	default:
		return Version{}, fmt.Errorf("%w %q", ErrUnknownScheme, scheme)
	}
	if err != nil {
		return Version{}, fmt.Errorf("%w %q (%s): %w", ErrInvalid, s, scheme, err)
	}
	v.scheme = scheme
	return v, nil
}

// Scheme returns the scheme the version was parsed in.
func (v Version) Scheme() Scheme { return v.scheme }

// String returns the version as written, without a leading v.
func (v Version) String() string { return v.raw }

// IsBranch reports whether the version names a release branch (pg 17, semver 3.2) rather
// than one release. A branch stands for every release in it, which is what a floating
// image tag such as postgres:17 or traefik:v3.2 runs.
func (v Version) IsBranch() bool { return v.depth > 0 }

// Compare orders two versions of the same scheme: -1, 0 or +1. A branch compares as its
// first release (17 equals 17.0). Opaque versions only compare equal or not; unequal
// opaque versions are ordered by their text, which carries no meaning.
func Compare(a, b Version) int {
	if a.scheme != b.scheme {
		return strings.Compare(string(a.scheme)+a.raw, string(b.scheme)+b.raw)
	}
	switch a.scheme {
	case SchemeDpkg:
		return compareDeb(a.deb, b.deb)
	case SchemeOpaque:
		return strings.Compare(a.raw, b.raw)
	default:
		return compareNumeric(a, b)
	}
}

// Known reports whether the scheme is one of the schemes of schemas/v1.
func (s Scheme) Known() bool {
	switch s {
	case SchemeSemver, SchemePG, SchemeCalver, SchemeDpkg, SchemeKernel, SchemeOpaque:
		return true
	}
	return false
}

// comparable reports whether the scheme orders versions.
func (s Scheme) comparable() bool { return s != SchemeOpaque }

// branchLow is the first release of a branch (17 -> 17.0, 3.2 -> 3.2.0), with no prerelease.
// Floating tags never point at prereleases, so a branch the user runs starts here.
func (v Version) branchLow() Version {
	low := v
	low.depth = 0
	return low
}

// rangeLow is the lowest version a range bound covers. For a branch written as a bound
// (introduced 17) it sits below every prerelease of the branch (17beta1 included).
func (v Version) rangeLow() Version {
	if v.depth == 0 {
		return v
	}
	low := v
	low.depth = 0
	low.floor = true
	return low
}

// releaseCeil is the first release at or above v: a prerelease or floor of 3.8.0 gives
// 3.8.0, a release gives itself.
func (v Version) releaseCeil() Version {
	r := v
	r.floor = false
	r.pre = nil
	return r
}

// branchHigh is the exclusive end of a branch: the floor of the next branch
// (17 -> below 18beta1, 3.2 -> below 3.3.0-rc.1).
func (v Version) branchHigh() Version {
	high := v
	high.nums = append([]uint64(nil), v.nums...)
	high.nums[v.depth-1]++
	for i := v.depth; i < len(high.nums); i++ {
		high.nums[i] = 0
	}
	high.depth = 0
	high.floor = true
	high.pre = nil
	return high
}

// compareNumeric orders numeric-component versions: release numbers, then floor below
// prerelease below release.
func compareNumeric(a, b Version) int {
	n := max(len(a.nums), len(b.nums))
	for i := range n {
		var x, y uint64
		if i < len(a.nums) {
			x = a.nums[i]
		}
		if i < len(b.nums) {
			y = b.nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	if a.floor || b.floor {
		switch {
		case a.floor && b.floor:
			return 0
		case a.floor:
			return -1
		default:
			return 1
		}
	}
	return comparePre(a.pre, b.pre)
}

// comparePre orders prerelease identifiers as semver does (a release sorts after every
// prerelease, numeric identifiers sort below alphanumeric ones), except that digit runs
// inside an alphanumeric identifier compare numerically, so rc10 sorts after rc2.
func comparePre(a, b []string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func compareIdent(a, b string) int {
	an, aNum := isDigits(a)
	bn, bNum := isDigits(b)
	switch {
	case aNum && bNum:
		return compareDigitRuns(an, bn)
	case aNum:
		return -1
	case bNum:
		return 1
	}
	return compareNatural(a, b)
}

// compareNatural compares alternating letter and digit runs; digit runs numerically.
func compareNatural(a, b string) int {
	for a != "" && b != "" {
		ra, restA := splitRun(a)
		rb, restB := splitRun(b)
		_, da := isDigits(ra)
		_, db := isDigits(rb)
		var c int
		switch {
		case da && db:
			c = compareDigitRuns(ra, rb)
		case da:
			c = -1
		case db:
			c = 1
		default:
			c = strings.Compare(ra, rb)
		}
		if c != 0 {
			return c
		}
		a, b = restA, restB
	}
	return cmpInt(len(a), len(b))
}

// splitRun splits s after its leading run of digits or of non-digits.
func splitRun(s string) (string, string) {
	digit := isDigit(s[0])
	i := 1
	for i < len(s) && isDigit(s[i]) == digit {
		i++
	}
	return s[:i], s[i:]
}

// compareDigitRuns compares two digit strings numerically without overflow.
func compareDigitRuns(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isDigits reports whether s is a non-empty run of ASCII digits.
func isDigits(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return s, false
		}
	}
	return s, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// parseUint reads a component made only of digits; leading zeros are allowed.
func parseUint(s string) (uint64, error) {
	if _, ok := isDigits(s); !ok {
		return 0, fmt.Errorf("component %q is not a number", s)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("component %q is too large", s)
	}
	return n, nil
}

// parseNums reads dot-separated numeric components.
func parseNums(s string, minParts, maxParts int) ([]uint64, error) {
	parts := strings.Split(s, ".")
	if len(parts) < minParts || len(parts) > maxParts {
		return nil, fmt.Errorf("want %d to %d numeric components, got %d", minParts, maxParts, len(parts))
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, err := parseUint(p)
		if err != nil {
			return nil, err
		}
		nums[i] = n
	}
	return nums, nil
}

func pad(nums []uint64, n int) []uint64 {
	for len(nums) < n {
		nums = append(nums, 0)
	}
	return nums
}

// parsePre reads dot-separated prerelease identifiers made of [0-9A-Za-z-].
func parsePre(s string) ([]string, error) {
	ids := strings.Split(s, ".")
	for _, id := range ids {
		if id == "" {
			return nil, errors.New("empty prerelease identifier")
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			if !isDigit(c) && !isLetter(c) && c != '-' {
				return nil, fmt.Errorf("prerelease identifier %q has %q", id, c)
			}
		}
	}
	return ids, nil
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func parseSemver(s string) (Version, error) {
	raw := s
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
		raw = s
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if _, err := parsePre(s[i+1:]); err != nil {
			return Version{}, fmt.Errorf("build metadata: %w", err)
		}
		s = s[:i]
	}
	core, preText, hasPre := strings.Cut(s, "-")
	nums, err := parseNums(core, 1, 3)
	if err != nil {
		return Version{}, err
	}
	v := Version{raw: raw}
	if hasPre {
		if v.pre, err = parsePre(preText); err != nil {
			return Version{}, err
		}
	} else if len(nums) < 3 {
		v.depth = len(nums)
	}
	v.nums = pad(nums, 3)
	return v, nil
}

// splitPGPre splits a trailing alpha, beta or rc prerelease (18beta1) off a pg version.
func splitPGPre(s string) (string, []string, error) {
	for _, tag := range []string{"alpha", "beta", "rc"} {
		i := strings.Index(s, tag)
		if i < 0 {
			continue
		}
		n := s[i+len(tag):]
		if _, ok := isDigits(n); !ok {
			return "", nil, fmt.Errorf("prerelease %q needs a number", s[i:])
		}
		return s[:i], []string{tag, n}, nil
	}
	return s, nil, nil
}

func parsePG(s string) (Version, error) {
	core, pre, err := splitPGPre(s)
	if err != nil {
		return Version{}, err
	}
	nums, err := parseNums(core, 1, 3)
	if err != nil {
		return Version{}, err
	}
	// Since 10 a release is major.minor; before, major.minor.patch.
	width := 3
	if nums[0] >= 10 {
		width = 2
	}
	if len(nums) > width {
		return Version{}, fmt.Errorf("PostgreSQL %d has at most %d components", nums[0], width)
	}
	v := Version{raw: s, pre: pre}
	if pre == nil && len(nums) < width {
		v.depth = len(nums)
	}
	v.nums = pad(nums, width)
	return v, nil
}

func parseCalver(s string) (Version, error) {
	core, preText, hasPre := strings.Cut(s, "-")
	nums, err := parseNums(core, 1, 6)
	if err != nil {
		return Version{}, err
	}
	v := Version{raw: s, nums: nums}
	if hasPre {
		if v.pre, err = parsePre(preText); err != nil {
			return Version{}, err
		}
	}
	return v, nil
}

func parseKernel(s string) (Version, error) {
	core, rc, hasRC := strings.Cut(s, "-")
	nums, err := parseNums(core, 2, 3)
	if err != nil {
		return Version{}, err
	}
	v := Version{raw: s, nums: pad(nums, 3)}
	if hasRC {
		n, ok := strings.CutPrefix(rc, "rc")
		if _, digits := isDigits(n); !ok || !digits {
			return Version{}, fmt.Errorf("suffix %q is not an upstream -rcN; distro kernels need a distro notice", rc)
		}
		v.pre = []string{"rc", n}
	}
	return v, nil
}

func parseOpaque(s string) (Version, error) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f {
			return Version{}, fmt.Errorf("byte %#x is not printable ASCII", c)
		}
	}
	return Version{raw: s}, nil
}
