package matching

import (
	"bytes"
	"os"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
	"github.com/Shironex/advisorydeck/image/internal/feed"
)

func loadPostgres(t *testing.T) *feed.ProductFeed {
	t.Helper()
	raw, err := os.ReadFile(contracttest.Path(t, "fixtures/api/v1/products/postgresql.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := feed.DecodeProductFeed(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStubAgainstFixture(t *testing.T) {
	p := loadPostgres(t)
	a := p.Advisories[0]
	cases := []struct {
		version string
		want    Verdict
	}{
		{"17", Affected},   // floating branch, fixed in 17.12
		{"17.4", Affected}, // exact, before the fix
		{"17.12", NotAffected},
		{"18.7", NotAffected},
		{"14.3", Affected},   // introduced "0"
		{"13", Affected},     // EOL branch below 14.25
		{"19", NotAffected},  // newer than every range
		{"17beta1", Unknown}, // not a plain dotted version
	}
	for _, tc := range cases {
		got := Stub{}.Match(Declared{Product: "postgresql", Version: tc.version}, p.Product, a)
		if got.Verdict != tc.want {
			t.Errorf("%s: %s (%s), want %s", tc.version, got.Verdict, got.Reason, tc.want)
		}
		if got.Reason == "" {
			t.Errorf("%s: empty reason", tc.version)
		}
	}
}

func TestStubUnknowns(t *testing.T) {
	p := loadPostgres(t)
	a := p.Advisories[0]

	empty := a
	empty.Affected = []feed.Affected{{Product: "postgresql"}}
	if got := (Stub{}).Match(Declared{Product: "postgresql", Version: "17"}, p.Product, empty); got.Verdict != Unknown {
		t.Errorf("empty ranges: %s", got.Verdict)
	}
	if got := (Stub{}).Match(Declared{Product: "redis", Version: "8"}, p.Product, a); got.Verdict != Unknown {
		t.Errorf("product not listed: %s", got.Verdict)
	}
	dpkg := p.Product
	dpkg.VersionScheme = "dpkg"
	if got := (Stub{}).Match(Declared{Product: "postgresql", Version: "17"}, dpkg, a); got.Verdict != Unknown {
		t.Errorf("dpkg scheme: %s", got.Verdict)
	}
}

func TestStubOpenAndLastAffected(t *testing.T) {
	info := feed.ProductInfo{Slug: "traefik", VersionScheme: "semver"}
	adv := feed.Advisory{Affected: []feed.Affected{{Product: "traefik", Ranges: []feed.Range{
		{Introduced: "3.0.0", LastAffected: "3.1.2"},
		{Introduced: "3.5.0"},
	}}}}
	cases := map[string]Verdict{"3.1.2": Affected, "3.1.3": NotAffected, "2.11.0": NotAffected, "3.6.1": Affected}
	for v, want := range cases {
		if got := (Stub{}).Match(Declared{Product: "traefik", Version: v}, info, adv); got.Verdict != want {
			t.Errorf("%s: %s (%s), want %s", v, got.Verdict, got.Reason, want)
		}
	}
}

func TestFuncAdapter(t *testing.T) {
	var m Matcher = Func(func(Declared, feed.ProductInfo, feed.Advisory) Result {
		return Result{Verdict: NotAffected, Reason: "adapter"}
	})
	if got := m.Match(Declared{}, feed.ProductInfo{}, feed.Advisory{}); got.Reason != "adapter" {
		t.Fatal(got)
	}
}
