package match

import (
	"errors"
	"fmt"
	"strings"
)

// debVersion is a Debian package version: [epoch:]upstream[-revision].
type debVersion struct {
	epoch    uint64
	upstream string
	revision string
}

// parseDpkg follows deb-version(7): the epoch is the digits before the first colon, the
// revision is everything after the last hyphen, and the upstream part must start with a
// digit. A missing revision compares equal to revision 0, as dpkg does.
func parseDpkg(s string) (Version, error) {
	var d debVersion
	rest := s
	if before, after, ok := strings.Cut(s, ":"); ok {
		n, err := parseUint(before)
		if err != nil {
			return Version{}, fmt.Errorf("epoch: %w", err)
		}
		d.epoch, rest = n, after
	}
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		d.upstream, d.revision = rest[:i], rest[i+1:]
		if d.revision == "" {
			return Version{}, errors.New("empty revision after the last hyphen")
		}
	} else {
		d.upstream = rest
	}
	if d.upstream == "" || !isDigit(d.upstream[0]) {
		return Version{}, errors.New("upstream version must start with a digit")
	}
	if err := checkDebChars(d.upstream, ".+~-:"); err != nil {
		return Version{}, fmt.Errorf("upstream: %w", err)
	}
	if err := checkDebChars(d.revision, ".+~"); err != nil {
		return Version{}, fmt.Errorf("revision: %w", err)
	}
	return Version{raw: s, deb: d}, nil
}

func checkDebChars(s, extra string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isDigit(c) && !isLetter(c) && strings.IndexByte(extra, c) < 0 {
			return fmt.Errorf("character %q is not allowed", c)
		}
	}
	return nil
}

func compareDeb(a, b debVersion) int {
	if a.epoch != b.epoch {
		if a.epoch < b.epoch {
			return -1
		}
		return 1
	}
	if c := verrevcmp(a.upstream, b.upstream); c != 0 {
		return c
	}
	return verrevcmp(a.revision, b.revision)
}

// debOrder is the dpkg sort weight of one character in a non-digit run: ~ sorts before
// the end of the string, which sorts before letters, which sort before everything else.
func debOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case isLetter(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp is dpkg's comparison of an upstream version or a revision: alternating
// non-digit runs (compared with debOrder) and digit runs (compared numerically).
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := debOrder(a, i), debOrder(b, j)
			if ac != bc {
				return cmpInt(ac, bc)
			}
			i++
			j++
		}
		si := i
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		sj := j
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := compareDigitRuns(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}
