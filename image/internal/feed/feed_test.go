package feed

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
)

func TestFixturesDecodeAndAgree(t *testing.T) {
	manifestBytes, err := os.ReadFile(contracttest.Path(t, "fixtures/api/v1/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeManifest(bytes.NewReader(manifestBytes))
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := m.Products["postgresql"]
	if !ok {
		t.Fatal("manifest has no postgresql entry")
	}

	productBytes, err := os.ReadFile(contracttest.Path(t, "fixtures/api/v1/products/postgresql.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := ETag(productBytes); got != entry.ETag {
		t.Fatalf("etag = %s, manifest says %s", got, entry.ETag)
	}
	p, err := DecodeProductFeed(bytes.NewReader(productBytes))
	if err != nil {
		t.Fatal(err)
	}
	if p.Product.VersionScheme != "pg" || len(p.Advisories) != entry.Advisories {
		t.Fatalf("product feed = %+v", p.Product)
	}
	a := p.Advisories[0]
	if a.ID != "CVE-2026-120154" || a.Severity.Level != "medium" || a.EPSS == nil || a.EPSS.Percentile != 0.22351 || a.Note == nil {
		t.Fatalf("advisory = %+v", a)
	}
	if a.KEV.State() != KEVNotListed {
		t.Errorf("kev state = %s, want not-listed (checked)", a.KEV.State())
	}
	if r := a.Affected[0].Ranges[1]; r.Introduced != "17" || r.Fixed != "17.12" {
		t.Errorf("second range = %+v", r)
	}
	if a.Note.Status != "reviewed" || len(a.Note.Assumptions) == 0 {
		t.Errorf("note = %+v", a.Note)
	}
}

func TestFixturesMatchSchemas(t *testing.T) {
	for file, schema := range map[string]string{
		"fixtures/api/v1/manifest.json":                 "manifest",
		"fixtures/api/v1/products/postgresql.json":      "product-feed",
		"fixtures/data/advisories/CVE-2026-120154.json": "advisory",
	} {
		if err := contracttest.Schema(t, schema).Validate(contracttest.LoadData(t, contracttest.Path(t, file))); err != nil {
			t.Errorf("%s: %v", file, err)
		}
	}
}

func TestDecodeRejectsOtherSchemas(t *testing.T) {
	if _, err := DecodeManifest(strings.NewReader(`{"schema":"advisorydeck/v2/manifest"}`)); err == nil {
		t.Error("v2 manifest accepted")
	}
	if _, err := DecodeProductFeed(strings.NewReader(`{"schema":"advisorydeck/v1/manifest"}`)); err == nil {
		t.Error("manifest accepted as product feed")
	}
}

func TestUnknownFieldsAreIgnored(t *testing.T) {
	m, err := DecodeManifest(strings.NewReader(`{"schema":"advisorydeck/v1/manifest","generated_at":"2026-11-13T09:00:00Z","products":{},"future":true}`))
	if err != nil || m == nil {
		t.Fatalf("additive field broke decoding: %v", err)
	}
}

func TestKEVStates(t *testing.T) {
	for raw, want := range map[string]string{
		`{"listed":true,"added_at":"2026-11-15","checked":true}`: KEVListed,
		`{"listed":false,"added_at":null,"checked":true}`:        KEVNotListed,
		`{"listed":false,"added_at":null,"checked":false}`:       KEVNotChecked,
		// A feed from before enrichment: no checked field. Never "not listed".
		`{"listed":false,"added_at":null}`: KEVNotChecked,
		`{"listed":true,"added_at":null}`:  KEVListed,
	} {
		var k KEV
		if err := json.Unmarshal([]byte(raw), &k); err != nil {
			t.Fatal(err)
		}
		if got := k.State(); got != want {
			t.Errorf("%s: state %s, want %s", raw, got, want)
		}
	}
}
