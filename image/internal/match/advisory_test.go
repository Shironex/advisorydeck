package match

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
	"github.com/Shironex/advisorydeck/image/internal/feed"
)

// The vectors in fixtures/match are plain JSON so a TypeScript port can run the same
// cases. The advisory vectors come from real advisories, each verified against its source
// on 2026-11-16 (the source URL and the ranges as published are in each vector):
//
//   - postgresql.json: CVE-2026-120154, the CNA record by PostgreSQL in cvelistV5
//     (cves/2026/120xxx/CVE-2026-120154.json), five branch ranges 18, 17, 16, 15 and 0.
//   - traefik.json: GHSA-p956-6gvv-mxqp (v2 and v3 modules plus an rc-only range) and
//     GHSA-53qr-784g-cj35 (a range that starts at 3.2.0), traefik/traefik repo advisories.
//   - coolify.json: the June and July 2026 batch on coollabsio/coolify, GHSA-chg4-63hm-xv9x,
//     GHSA-w8wm-r924-f65v, GHSA-725v-f5gh-22q9 and GHSA-6pmw-6m96-4v4m.
//   - redis.json: GHSA-c8h9-259x-jff4 (All / TBD), its CVE record CVE-2026-25243 (< 8.6.3),
//     GHSA-8ghh-qpmp-7826 (>= 7.0.0, TBD) and GHSA-4789-qfc9-5f9q (one fix per branch).
//   - docker-engine.json: moby/moby GHSA-6jhp-7446-hf7f (CVE-2026-115538, < 29.9.3) and
//     GHSA-v23v-6jw2-98fq (CVE-2024-41110, docker-ce last affected list with 19.03.15).
//
// Products the catalog does not hold yet carry the record shapes ingest learned to read:
//
//   - n8n.json, keycloak.json, authentik.json, php.json: one upper bound per branch on
//     separate entries (GHSA-c772-hjfp-gfc2, GHSA-95cx-vmr5-3cmr, GHSA-cxwx-9x59-28qm,
//     GHSA-w8hw-w9fx-j79w), read as one range per branch.
//   - mysql.json, mariadb.json: hyphen ranges without spaces (CVE-2026-101801 8.4.0-8.4.12,
//     GHSA-m5gf-432r-g5jw 10.6.1-10.6.27), read as ranges rather than one prerelease.
//   - nextcloud.json: lower bounds next to a patched list of the same length
//     (GHSA-f99w-3pm7-v4cv), paired into one range per branch.

type advisoryVectors struct {
	Product    string `json:"product"`
	Scheme     Scheme `json:"scheme"`
	Advisories []struct {
		ID            string       `json:"id"`
		Source        string       `json:"source"`
		Verified      string       `json:"verified"`
		Published     []string     `json:"published"`
		Normalization string       `json:"normalization"`
		Ranges        []feed.Range `json:"ranges"`
		Cases         []struct {
			Version string `json:"version"`
			Outcome string `json:"outcome"`
			Reason  Reason `json:"reason"`
			Fixed   string `json:"fixed"`
		} `json:"cases"`
	} `json:"advisories"`
}

func TestAdvisoryVectors(t *testing.T) {
	files, err := filepath.Glob(contracttest.Path(t, "fixtures/match/advisories/*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 5 {
		t.Fatalf("found %d advisory vector files, want one per catalog product", len(files))
	}
	total := 0
	for _, path := range files {
		rel, _ := filepath.Rel(contracttest.RepoRoot(t), path)
		var vec advisoryVectors
		readJSON(t, filepath.ToSlash(rel), &vec)
		for _, adv := range vec.Advisories {
			if adv.Source == "" || adv.Verified == "" || len(adv.Published) == 0 || len(adv.Cases) == 0 {
				t.Errorf("%s %s: needs source, verified, published and cases", rel, adv.ID)
			}
			a := feed.Advisory{ID: adv.ID, Affected: []feed.Affected{{Product: vec.Product, Ranges: adv.Ranges}}}
			for _, c := range adv.Cases {
				total++
				got := Check(vec.Scheme, c.Version, vec.Product, a)
				if got.Outcome.String() != c.Outcome || got.Reason != c.Reason || got.FixedIn != c.Fixed {
					t.Errorf("%s %s at %s = %s/%s fixed %q (%s), want %s/%s fixed %q",
						vec.Product, adv.ID, c.Version, got.Outcome, got.Reason, got.FixedIn, got.Detail,
						c.Outcome, c.Reason, c.Fixed)
				}
				if got.Outcome == OutcomeAffected && got.Range == nil {
					t.Errorf("%s %s at %s: affected without the deciding range", vec.Product, adv.ID, c.Version)
				}
				if got.Detail == "" {
					t.Errorf("%s %s at %s: empty detail", vec.Product, adv.ID, c.Version)
				}
			}
		}
	}
	t.Logf("%d advisory cases", total)
}

// TestPostgresFeedFixture runs the PostgreSQL vectors through the published feed fixture,
// so the matcher and fixtures/api/v1/products/postgresql.json agree.
func TestPostgresFeedFixture(t *testing.T) {
	raw, err := os.ReadFile(contracttest.Path(t, "fixtures/api/v1/products/postgresql.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := feed.DecodeProductFeed(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var vec advisoryVectors
	readJSON(t, "fixtures/match/advisories/postgresql.json", &vec)
	want := vec.Advisories[0]
	adv := p.Advisories[0]
	if adv.ID != want.ID || !reflect.DeepEqual(adv.Affected[0].Ranges, want.Ranges) {
		t.Fatalf("feed fixture %s ranges %+v differ from the vector %s %+v", adv.ID, adv.Affected[0].Ranges, want.ID, want.Ranges)
	}
	scheme := Scheme(p.Product.VersionScheme)
	for _, c := range want.Cases {
		if got := Check(scheme, c.Version, p.Product.Slug, adv); got.Outcome.String() != c.Outcome {
			t.Errorf("%s = %s, want %s", c.Version, got.Outcome, c.Outcome)
		}
	}
	// Every branch the feed lists is affected (each has a range), and its latest release is
	// the fix, so it is not affected.
	for _, b := range p.Product.Branches {
		if got := Check(scheme, b.Name, p.Product.Slug, adv); got.Outcome != OutcomeAffected || !got.Branch {
			t.Errorf("branch %s = %+v", b.Name, got)
		}
		if got := Check(scheme, *b.Latest, p.Product.Slug, adv); got.Outcome != OutcomeNotAffected {
			t.Errorf("latest %s = %+v", *b.Latest, got)
		}
	}
}
