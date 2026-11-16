package match

import "testing"

// Run one target at a time, for example:
//
//	go test ./internal/match -run '^$' -fuzz FuzzParse -fuzztime 60s
//
// Plain go test runs the seeds below as regular tests.

var fuzzSchemes = []Scheme{SchemeSemver, SchemePG, SchemeCalver, SchemeDpkg, SchemeKernel, SchemeOpaque}

var fuzzSeeds = []string{
	"0", "1.2.3", "v3.7.18", "19.03.15", "4.0.0-beta.474", "8.0-rc1", "1.0.0-alpha.beta+build.1",
	"17", "17.12", "9.6.24", "18beta1", "9.6rc1", "2024.10.1", "6.12-rc3", "6.1.115",
	"1:9.2p1-2+deb12u3", "1.0~rc1-1", "5.15.0-122.132", "1.0~~", "latest", "All", "TBD", "",
	"1..2", "1.2.3-", "-", ":", "~", "99999999999999999999",
}

func schemeOf(i uint8) Scheme { return fuzzSchemes[int(i)%len(fuzzSchemes)] }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// FuzzParse checks that parsing never panics and that a parsed version is stable: it
// equals itself, and its String form parses back to an equal version of the same kind.
func FuzzParse(f *testing.F) {
	for i := range fuzzSchemes {
		for _, s := range fuzzSeeds {
			f.Add(uint8(i), s)
		}
	}
	f.Fuzz(func(t *testing.T, si uint8, s string) {
		scheme := schemeOf(si)
		v, err := Parse(scheme, s)
		if err != nil {
			return
		}
		if Compare(v, v) != 0 {
			t.Fatalf("%s %q: not equal to itself", scheme, s)
		}
		w, err := Parse(scheme, v.String())
		if err != nil {
			t.Fatalf("%s %q: String %q does not parse: %v", scheme, s, v.String(), err)
		}
		if Compare(v, w) != 0 || v.IsBranch() != w.IsBranch() {
			t.Fatalf("%s %q: reparse of %q differs", scheme, s, v.String())
		}
		if v.IsBranch() {
			if Compare(v.branchLow(), v.branchHigh()) >= 0 {
				t.Fatalf("%s %q: empty branch", scheme, s)
			}
		}
	})
}

// FuzzCompare checks that Compare is a total order on parsed versions: antisymmetric and
// transitive.
func FuzzCompare(f *testing.F) {
	for i := range fuzzSchemes {
		f.Add(uint8(i), "1.2.3", "1.2.3-rc.1", "1.10")
		f.Add(uint8(i), "17", "17.0", "18beta1")
		f.Add(uint8(i), "1:1.0", "1.0~", "1.0+b1")
	}
	f.Fuzz(func(t *testing.T, si uint8, a, b, c string) {
		scheme := schemeOf(si)
		va, errA := Parse(scheme, a)
		vb, errB := Parse(scheme, b)
		vc, errC := Parse(scheme, c)
		if errA != nil || errB != nil || errC != nil {
			return
		}
		ab, ba := Compare(va, vb), Compare(vb, va)
		if sign(ab) != -sign(ba) {
			t.Fatalf("%s: compare(%q,%q)=%d but compare(%q,%q)=%d", scheme, a, b, ab, b, a, ba)
		}
		bc, ac := Compare(vb, vc), Compare(va, vc)
		if ab <= 0 && bc <= 0 && ac > 0 {
			t.Fatalf("%s: %q <= %q <= %q but %q > %q", scheme, a, b, c, a, c)
		}
	})
}
