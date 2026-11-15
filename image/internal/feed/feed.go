// Package feed holds the types of the published v1 feed (manifest.json and
// products/<slug>.json) as described by schemas/v1. Unknown fields are ignored so that
// additive v1 changes never break an installed image.
package feed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Schema markers carried in the documents.
const (
	ManifestSchema    = "advisorydeck/v1/manifest"
	ProductFeedSchema = "advisorydeck/v1/product-feed"
)

// Manifest lists every published product and the etag of its file.
type Manifest struct {
	Schema      string                   `json:"schema"`
	GeneratedAt time.Time                `json:"generated_at"`
	Products    map[string]ManifestEntry `json:"products"`
}

// ManifestEntry describes one products/<slug>.json.
type ManifestEntry struct {
	UpdatedAt  time.Time `json:"updated_at"`
	ETag       string    `json:"etag"`
	Advisories int       `json:"advisories"`
}

// ProductFeed is everything needed to match one product locally.
type ProductFeed struct {
	Schema      string      `json:"schema"`
	GeneratedAt time.Time   `json:"generated_at"`
	Product     ProductInfo `json:"product"`
	Advisories  []Advisory  `json:"advisories"`
}

// ProductInfo is the catalog data a consumer needs.
type ProductInfo struct {
	Slug          string   `json:"slug"`
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	Homepage      string   `json:"homepage"`
	VersionScheme string   `json:"version_scheme"`
	Branches      []Branch `json:"branches"`
}

// Branch is a release branch and its support state.
type Branch struct {
	Name    string  `json:"name"`
	EOL     bool    `json:"eol"`
	EOLDate *string `json:"eol_date"`
	Latest  *string `json:"latest"`
}

// Advisory is one alias cluster.
type Advisory struct {
	ID          string      `json:"id"`
	Aliases     []string    `json:"aliases"`
	Title       string      `json:"title"`
	Summary     string      `json:"summary"`
	PublishedAt time.Time   `json:"published_at"`
	ModifiedAt  time.Time   `json:"modified_at"`
	Severity    Severity    `json:"severity"`
	KEV         KEV         `json:"kev"`
	EPSS        *EPSS       `json:"epss"`
	CWEs        []string    `json:"cwes"`
	Affected    []Affected  `json:"affected"`
	References  []Reference `json:"references"`
	Sources     []Source    `json:"sources"`
	Revision    string      `json:"revision"`
	Note        *Note       `json:"note"`
}

// Severity is the qualitative level plus the score it came from.
type Severity struct {
	Level  string   `json:"level"`
	Score  *float64 `json:"score"`
	Vector *string  `json:"vector"`
	Source string   `json:"source"`
}

// KEV says whether the advisory is in the CISA Known Exploited Vulnerabilities catalog.
type KEV struct {
	Listed  bool    `json:"listed"`
	AddedAt *string `json:"added_at"`
}

// EPSS is the FIRST exploit prediction score.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// Affected lists the affected ranges of one product. No ranges means unknown: never
// report "not affected" for it.
type Affected struct {
	Product string  `json:"product"`
	Ranges  []Range `json:"ranges"`
}

// Range is introduced (inclusive) up to fixed (exclusive) or last_affected (inclusive).
type Range struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Reference is a link about the advisory.
type Reference struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

// Source is a record the advisory was built from, for attribution.
type Source struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	URL     string `json:"url"`
	License string `json:"license"`
}

// Note is a reviewed curated note.
type Note struct {
	Status      string   `json:"status"`
	Audience    string   `json:"audience"`
	Exposure    string   `json:"exposure"`
	Assumptions []string `json:"assumptions"`
	Actions     []Action `json:"actions"`
	Authorship  string   `json:"authorship"`
	ReviewedBy  string   `json:"reviewed_by"`
	ReviewedAt  string   `json:"reviewed_at"`
	Body        string   `json:"body"`
}

// Action is one step of a curated note.
type Action struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
	Code string `json:"code,omitempty"`
}

// DecodeManifest reads a manifest and checks its schema marker.
func DecodeManifest(r io.Reader) (*Manifest, error) {
	var m Manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != ManifestSchema {
		return nil, fmt.Errorf("manifest: schema %q, want %q", m.Schema, ManifestSchema)
	}
	return &m, nil
}

// DecodeProductFeed reads a product file and checks its schema marker.
func DecodeProductFeed(r io.Reader) (*ProductFeed, error) {
	var p ProductFeed
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return nil, fmt.Errorf("product feed: %w", err)
	}
	if p.Schema != ProductFeedSchema {
		return nil, fmt.Errorf("product feed: schema %q, want %q", p.Schema, ProductFeedSchema)
	}
	return &p, nil
}

// ETag returns the manifest etag of exact file bytes.
func ETag(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
