package match

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
	"github.com/Shironex/advisorydeck/image/internal/feed"
)

func TestZeroTagKindIsFloating(t *testing.T) {
	var k TagKind
	if k != TagFloating || k.String() != "floating" {
		t.Fatalf("zero TagKind = %v", k)
	}
}

// catalogImage reads the version scheme and the first image of a catalog product.
func catalogImage(t *testing.T, slug string) (Scheme, string) {
	t.Helper()
	paths, err := filepath.Glob(contracttest.Path(t, "catalog/*/"+slug+".yml"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("catalog entry for %s: %v %v", slug, paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		VersionScheme Scheme `yaml:"version_scheme"`
		Images        []struct {
			TagPattern string `yaml:"tag_pattern"`
		} `yaml:"images"`
	}
	if err := yaml.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Images) == 0 {
		t.Fatalf("%s has no image", slug)
	}
	return p.VersionScheme, p.Images[0].TagPattern
}

func TestTagVectors(t *testing.T) {
	var vec struct {
		Description string `json:"description"`
		Cases       []struct {
			Product string `json:"product"`
			Tag     string `json:"tag"`
			Kind    string `json:"kind"`
			Version string `json:"version"`
		} `json:"cases"`
	}
	readJSON(t, "fixtures/match/tags.json", &vec)
	patterns := map[string]*TagPattern{}
	for _, c := range vec.Cases {
		p, ok := patterns[c.Product]
		if !ok {
			scheme, pattern := catalogImage(t, c.Product)
			var err error
			if p, err = NewTagPattern(scheme, pattern); err != nil {
				t.Fatalf("%s: %v", c.Product, err)
			}
			patterns[c.Product] = p
		}
		got := p.Resolve(c.Tag)
		if got.Kind.String() != c.Kind || (got.Kind != TagFloating && got.Version.String() != c.Version) {
			t.Errorf("%s:%s = %s %q (%s), want %s %q", c.Product, c.Tag, got.Kind, got.Version, got.Detail, c.Kind, c.Version)
		}
		if got.Kind == TagFloating && got.Detail == "" {
			t.Errorf("%s:%s: floating without detail", c.Product, c.Tag)
		}
	}
}

func TestNewTagPatternErrors(t *testing.T) {
	if _, err := NewTagPattern("rpm", "^(?<version>.*)$"); !errors.Is(err, ErrUnknownScheme) {
		t.Errorf("unknown scheme: %v", err)
	}
	if _, err := NewTagPattern(SchemeSemver, "^([0-9]+)$"); err == nil {
		t.Error("pattern without a version group accepted")
	}
	if _, err := NewTagPattern(SchemeSemver, "^(?<version>[0-9]+$"); err == nil {
		t.Error("broken pattern accepted")
	}
}

// TestCheckTag uses the real PostgreSQL catalog pattern and the CVE-2026-120154 ranges
// (fixtures/match/advisories/postgresql.json).
func TestCheckTag(t *testing.T) {
	scheme, pattern := catalogImage(t, "postgresql")
	p, err := NewTagPattern(scheme, pattern)
	if err != nil {
		t.Fatal(err)
	}
	adv := feed.Advisory{ID: "CVE-2026-120154", Affected: []feed.Affected{{Product: "postgresql", Ranges: []feed.Range{
		{Introduced: "18", Fixed: "18.7"},
		{Introduced: "17", Fixed: "17.12"},
		{Introduced: "16", Fixed: "16.16"},
		{Introduced: "15", Fixed: "15.20"},
		{Introduced: "0", Fixed: "14.25"},
	}}}}
	tests := []struct {
		tag     string
		outcome Outcome
		reason  Reason
		branch  bool
	}{
		{"latest", OutcomeUnknown, ReasonFloatingTag, false},
		{"alpine", OutcomeUnknown, ReasonFloatingTag, false},
		{"17", OutcomeAffected, ReasonBranchInRange, true},
		{"17-alpine", OutcomeAffected, ReasonBranchInRange, true},
		{"17.4", OutcomeAffected, ReasonInRange, false},
		{"17.12-bookworm", OutcomeNotAffected, ReasonOutsideRanges, false},
		{"19", OutcomeNotAffected, ReasonOutsideRanges, true},
	}
	for _, tt := range tests {
		got := p.CheckTag(tt.tag, "postgresql", adv)
		if got.Outcome != tt.outcome || got.Reason != tt.reason || got.Branch != tt.branch {
			t.Errorf("postgres:%s = %s/%s branch %v (%s), want %s/%s branch %v",
				tt.tag, got.Outcome, got.Reason, got.Branch, got.Detail, tt.outcome, tt.reason, tt.branch)
		}
	}
}

// TestCatalogPatternsCompile proves every catalog tag pattern works in Go's RE2.
func TestCatalogPatternsCompile(t *testing.T) {
	for _, slug := range []string{"postgresql", "traefik", "redis", "coolify", "docker-engine"} {
		scheme, pattern := catalogImage(t, slug)
		if _, err := NewTagPattern(scheme, pattern); err != nil {
			t.Errorf("%s: %v", slug, err)
		}
	}
}
