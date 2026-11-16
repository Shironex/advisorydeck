package match

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
)

func readJSON(t *testing.T, rel string, v any) {
	t.Helper()
	raw, err := os.ReadFile(contracttest.Path(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
}

func TestVersionVectors(t *testing.T) {
	var vec struct {
		Description string `json:"description"`
		Compare     []struct {
			Scheme Scheme `json:"scheme"`
			A      string `json:"a"`
			B      string `json:"b"`
			Want   int    `json:"want"`
		} `json:"compare"`
		Branch []struct {
			Scheme  Scheme `json:"scheme"`
			Version string `json:"version"`
			Branch  bool   `json:"branch"`
		} `json:"branch"`
		Invalid []struct {
			Scheme  Scheme `json:"scheme"`
			Version string `json:"version"`
		} `json:"invalid"`
	}
	readJSON(t, "fixtures/match/versions.json", &vec)
	for _, c := range vec.Compare {
		a, errA := Parse(c.Scheme, c.A)
		b, errB := Parse(c.Scheme, c.B)
		if errA != nil || errB != nil {
			t.Errorf("%s: parse %q: %v, %q: %v", c.Scheme, c.A, errA, c.B, errB)
			continue
		}
		if got := Compare(a, b); got != c.Want {
			t.Errorf("%s: compare(%s, %s) = %d, want %d", c.Scheme, c.A, c.B, got, c.Want)
		}
		if got := Compare(b, a); got != -c.Want {
			t.Errorf("%s: compare(%s, %s) = %d, want %d", c.Scheme, c.B, c.A, got, -c.Want)
		}
	}
	for _, c := range vec.Branch {
		v, err := Parse(c.Scheme, c.Version)
		if err != nil {
			t.Errorf("%s %q: %v", c.Scheme, c.Version, err)
			continue
		}
		if v.IsBranch() != c.Branch {
			t.Errorf("%s %q: branch = %v, want %v", c.Scheme, c.Version, v.IsBranch(), c.Branch)
		}
	}
	for _, c := range vec.Invalid {
		if v, err := Parse(c.Scheme, c.Version); err == nil {
			t.Errorf("%s %q parsed as %+v, want an error", c.Scheme, c.Version, v)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse("rpm", "1.0"); !errors.Is(err, ErrUnknownScheme) {
		t.Errorf("unknown scheme error = %v", err)
	}
	if _, err := Parse(SchemeSemver, "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid error = %v", err)
	}
	if _, err := Parse(SchemeSemver, strings.Repeat("1", maxVersionLen+1)); !errors.Is(err, ErrInvalid) {
		t.Errorf("long version error = %v", err)
	}
}

func TestCompareAcrossSchemesIsStable(t *testing.T) {
	a, _ := Parse(SchemeSemver, "1.0.0")
	b, _ := Parse(SchemePG, "1.0")
	if Compare(a, b) != -Compare(b, a) || Compare(a, b) == 0 {
		t.Errorf("cross-scheme compare not antisymmetric")
	}
}
