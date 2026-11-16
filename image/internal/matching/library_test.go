package matching

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
	"github.com/Shironex/advisorydeck/image/internal/feed"
)

// vectors is the shape of fixtures/match/advisories/<product>.json.
type vectors struct {
	Product    string `json:"product"`
	Scheme     string `json:"scheme"`
	Advisories []struct {
		ID     string       `json:"id"`
		Ranges []feed.Range `json:"ranges"`
		Cases  []struct {
			Version string `json:"version"`
			Outcome string `json:"outcome"`
			Reason  string `json:"reason"`
			Fixed   string `json:"fixed"`
		} `json:"cases"`
	} `json:"advisories"`
}

// TestLibraryAgainstMatchVectors runs every real-advisory case of fixtures/match through
// the seam the daemon uses, so the wiring cannot drift from the matcher's own answers.
func TestLibraryAgainstMatchVectors(t *testing.T) {
	files, err := filepath.Glob(contracttest.Path(t, "fixtures/match/advisories/*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no vectors: %v", err)
	}
	want := map[string]Verdict{"affected": Affected, "not-affected": NotAffected, "unknown": Unknown}
	total := 0
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- repository fixture
		if err != nil {
			t.Fatal(err)
		}
		var v vectors
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		info := feed.ProductInfo{Slug: v.Product, VersionScheme: v.Scheme}
		for _, a := range v.Advisories {
			adv := feed.Advisory{ID: a.ID, Affected: []feed.Affected{{Product: v.Product, Ranges: a.Ranges}}}
			for _, c := range a.Cases {
				total++
				got := Library{}.Match(Declared{Product: v.Product, Version: c.Version}, info, adv)
				if got.Verdict != want[c.Outcome] || got.Code != c.Reason || got.FixedIn != c.Fixed {
					t.Errorf("%s %s %s: got %s/%s/%q, want %s/%s/%q", filepath.Base(f), a.ID, c.Version, got.Verdict, got.Code, got.FixedIn, c.Outcome, c.Reason, c.Fixed)
				}
				if got.Reason == "" {
					t.Errorf("%s %s: empty reason", a.ID, c.Version)
				}
			}
		}
	}
	t.Logf("%d cases from %d files", total, len(files))
}

func TestLibraryOnFeedFixture(t *testing.T) {
	raw, err := os.ReadFile(contracttest.Path(t, "fixtures/api/v1/products/postgresql.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := feed.DecodeProductFeed(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := Library{}.Match(Declared{Product: "postgresql", Version: "17"}, p.Product, p.Advisories[0])
	if got.Verdict != Affected || !got.Branch || got.FixedIn != "17.12" || !strings.Contains(got.Reason, "17.12") {
		t.Fatalf("branch 17: %+v", got)
	}
	if got := (Library{}).Match(Declared{Product: "redis", Version: "8"}, p.Product, p.Advisories[0]); got.Verdict != Unknown {
		t.Fatalf("product not listed: %+v", got)
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
