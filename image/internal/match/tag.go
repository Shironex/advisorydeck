package match

import (
	"fmt"
	"regexp"

	"github.com/Shironex/advisorydeck/image/internal/feed"
)

// TagKind says what an image tag tells about the version inside the image.
type TagKind int

// Tag kinds. The zero value is TagFloating, so an unresolved tag never reads as a version.
const (
	// TagFloating: the tag names no version (latest, alpine, a codename). Cannot tell.
	TagFloating TagKind = iota
	// TagBranch: the tag follows a branch (postgres:17, traefik:v3.2, redis:7-alpine).
	TagBranch
	// TagExact: the tag pins one release (postgres:17.4-alpine, traefik:v3.2.1).
	TagExact
)

// String returns floating, branch or exact (the names used by fixtures/match).
func (k TagKind) String() string {
	switch k {
	case TagBranch:
		return "branch"
	case TagExact:
		return "exact"
	default:
		return "floating"
	}
}

// Tag is a resolved image tag.
type Tag struct {
	Kind TagKind
	// Version is set for branch and exact tags.
	Version Version
	// Detail explains a floating tag.
	Detail string
}

// TagPattern resolves the tags of one catalog image (product.schema.json#/$defs/image).
type TagPattern struct {
	scheme  Scheme
	re      *regexp.Regexp
	version int
}

// NewTagPattern compiles a catalog tag_pattern. The pattern must have a named group
// version; the catalog anchors its patterns with ^ and $.
func NewTagPattern(scheme Scheme, pattern string) (*TagPattern, error) {
	if !scheme.Known() {
		return nil, fmt.Errorf("%w %q", ErrUnknownScheme, scheme)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("tag pattern: %w", err)
	}
	i := re.SubexpIndex("version")
	if i < 0 {
		return nil, fmt.Errorf("tag pattern %q has no (?<version>...) group", pattern)
	}
	return &TagPattern{scheme: scheme, re: re, version: i}, nil
}

// Resolve reads a tag. A tag that does not match the pattern, or whose version group does
// not parse in the scheme, is floating: the caller must say "cannot tell, check manually"
// instead of guessing.
func (p *TagPattern) Resolve(tag string) Tag {
	m := p.re.FindStringSubmatch(tag)
	if m == nil || m[p.version] == "" {
		return Tag{Detail: fmt.Sprintf("tag %q does not name a version; set the exact version instead", tag)}
	}
	v, err := Parse(p.scheme, m[p.version])
	if err != nil {
		return Tag{Detail: fmt.Sprintf("tag %q: %v; set the exact version instead", tag, err)}
	}
	if v.IsBranch() {
		return Tag{Kind: TagBranch, Version: v}
	}
	return Tag{Kind: TagExact, Version: v}
}

// CheckTag resolves an image tag and evaluates the advisory for it. A floating tag gives
// an unknown result with ReasonFloatingTag.
func (p *TagPattern) CheckTag(tag, slug string, adv feed.Advisory) Result {
	t := p.Resolve(tag)
	if t.Kind == TagFloating {
		return Result{Reason: ReasonFloatingTag, Detail: t.Detail + "; check manually"}
	}
	return CheckVersion(t.Version, slug, adv)
}
