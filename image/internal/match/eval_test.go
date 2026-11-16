package match

import (
	"strings"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/feed"
)

func TestZeroResultIsUnknown(t *testing.T) {
	var r Result
	if r.Outcome != OutcomeUnknown || r.Outcome.String() != "unknown" {
		t.Fatalf("zero Result = %v", r.Outcome)
	}
}

func TestEvaluateEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		scheme    Scheme
		installed string
		ranges    []feed.Range
		outcome   Outcome
		reason    Reason
		fixed     string
	}{
		{"nil ranges", SchemeSemver, "1.0.0", nil, OutcomeUnknown, ReasonNoRanges, ""},
		{"empty ranges for a branch", SchemePG, "17", []feed.Range{}, OutcomeUnknown, ReasonNoRanges, ""},
		{"unknown scheme", Scheme("rpm"), "1.0", []feed.Range{{Introduced: "0"}}, OutcomeUnknown, ReasonBadVersion, ""},
		{"introduced 0 only covers everything", SchemeSemver, "0.0.1", []feed.Range{{Introduced: "0"}}, OutcomeAffected, ReasonInRange, ""},
		{"bad range and no match is unknown", SchemeSemver, "1.0.0",
			[]feed.Range{{Introduced: "All", Fixed: "TBD"}}, OutcomeUnknown, ReasonBadRange, ""},
		{"bad range beside a matching one is affected", SchemeSemver, "1.0.0",
			[]feed.Range{{Introduced: "All"}, {Introduced: "0", Fixed: "1.0.1"}}, OutcomeAffected, ReasonInRange, "1.0.1"},
		{"bad range beside a non-matching one is unknown", SchemeSemver, "2.0.0",
			[]feed.Range{{Introduced: "0", Fixed: "1.0.1"}, {Introduced: "x"}}, OutcomeUnknown, ReasonBadRange, ""},
		{"fixed and last_affected together is a bad range", SchemeSemver, "1.0.0",
			[]feed.Range{{Introduced: "0", Fixed: "2.0.0", LastAffected: "1.9.0"}}, OutcomeUnknown, ReasonBadRange, ""},
		{"leading v in bounds", SchemeSemver, "3.7.17",
			[]feed.Range{{Introduced: "v3.0.0", Fixed: "v3.7.18"}}, OutcomeAffected, ReasonInRange, "v3.7.18"},
		{"fixed written as a branch excludes its prereleases", SchemePG, "18beta1",
			[]feed.Range{{Introduced: "17", Fixed: "18"}}, OutcomeNotAffected, ReasonOutsideRanges, ""},
		{"last_affected written as a branch covers the branch", SchemePG, "17.99",
			[]feed.Range{{Introduced: "17", LastAffected: "17"}}, OutcomeAffected, ReasonInRange, ""},
		{"last_affected branch stops before the next branch", SchemePG, "18beta1",
			[]feed.Range{{Introduced: "17", LastAffected: "17"}}, OutcomeNotAffected, ReasonOutsideRanges, ""},
		{"introduced branch includes its prereleases", SchemePG, "17rc1",
			[]feed.Range{{Introduced: "17", Fixed: "17.12"}}, OutcomeAffected, ReasonInRange, "17.12"},
		{"user branch never matches prerelease-only range", SchemeSemver, "3",
			[]feed.Range{{Introduced: "3.8.0-rc.1", Fixed: "3.8.0-rc.2"}}, OutcomeNotAffected, ReasonOutsideRanges, ""},
		{"user branch matches a range starting mid-branch", SchemeSemver, "3.7",
			[]feed.Range{{Introduced: "3.7.15", LastAffected: "3.7.17"}}, OutcomeAffected, ReasonBranchInRange, ""},
		{"user branch prefers the fix inside the branch", SchemeSemver, "8",
			[]feed.Range{{Introduced: "0", Fixed: "7.4.6"}, {Introduced: "8.0.0", Fixed: "8.0.4"}, {Introduced: "8.2.0", Fixed: "8.2.2"}},
			OutcomeAffected, ReasonBranchInRange, "8.2.2"},
		{"user branch beyond every range", SchemeSemver, "9",
			[]feed.Range{{Introduced: "8.0.0", Fixed: "8.2.2"}}, OutcomeNotAffected, ReasonOutsideRanges, ""},
		{"reversed range matches nothing", SchemeSemver, "1.5.0",
			[]feed.Range{{Introduced: "2.0.0", Fixed: "1.0.0"}}, OutcomeNotAffected, ReasonOutsideRanges, ""},
		{"dpkg backport fixed", SchemeDpkg, "1:9.2p1-2+deb12u4",
			[]feed.Range{{Introduced: "0", Fixed: "1:9.2p1-2+deb12u4"}}, OutcomeNotAffected, ReasonOutsideRanges, ""},
		{"dpkg before the backport", SchemeDpkg, "1:9.2p1-2+deb12u3",
			[]feed.Range{{Introduced: "0", Fixed: "1:9.2p1-2+deb12u4"}}, OutcomeAffected, ReasonInRange, "1:9.2p1-2+deb12u4"},
		{"dpkg tilde prerelease is before the fix", SchemeDpkg, "1:9.2p1-2+deb12u4~bpo1",
			[]feed.Range{{Introduced: "0", Fixed: "1:9.2p1-2+deb12u4"}}, OutcomeAffected, ReasonInRange, "1:9.2p1-2+deb12u4"},
		{"kernel stable fix", SchemeKernel, "6.1.118",
			[]feed.Range{{Introduced: "6.1.0", Fixed: "6.1.119"}}, OutcomeAffected, ReasonInRange, "6.1.119"},
		{"kernel distro string is unknown", SchemeKernel, "6.8.0-45-generic",
			[]feed.Range{{Introduced: "6.1.0", Fixed: "6.1.119"}}, OutcomeUnknown, ReasonBadVersion, ""},
		{"calver", SchemeCalver, "2024.10.2",
			[]feed.Range{{Introduced: "2024.1", Fixed: "2024.11"}}, OutcomeAffected, ReasonInRange, "2024.11"},
		{"opaque equal to last_affected", SchemeOpaque, "build-7",
			[]feed.Range{{Introduced: "build-1", LastAffected: "build-7"}}, OutcomeAffected, ReasonInRange, ""},
		{"opaque cannot order", SchemeOpaque, "build-5",
			[]feed.Range{{Introduced: "build-1", Fixed: "build-9"}}, OutcomeUnknown, ReasonNotComparable, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.scheme, tt.installed, tt.ranges)
			if got.Outcome != tt.outcome || got.Reason != tt.reason || got.FixedIn != tt.fixed {
				t.Errorf("got %s/%s fixed %q (%s), want %s/%s fixed %q",
					got.Outcome, got.Reason, got.FixedIn, got.Detail, tt.outcome, tt.reason, tt.fixed)
			}
			if got.Outcome == OutcomeUnknown && !strings.Contains(got.Detail, "check manually") {
				t.Errorf("unknown detail %q does not say check manually", got.Detail)
			}
		})
	}
}

func TestCheckEntries(t *testing.T) {
	ranges := []feed.Range{{Introduced: "0", Fixed: "29.9.3"}}
	tests := []struct {
		name     string
		affected []feed.Affected
		version  string
		outcome  Outcome
		reason   Reason
	}{
		{"product not listed", []feed.Affected{{Product: "redis", Ranges: ranges}}, "29.0.0", OutcomeUnknown, ReasonProductNotListed},
		{"no affected entries", nil, "29.0.0", OutcomeUnknown, ReasonProductNotListed},
		{"other product ignored", []feed.Affected{{Product: "redis", Ranges: nil}, {Product: "docker-engine", Ranges: ranges}}, "29.9.3", OutcomeNotAffected, ReasonOutsideRanges},
		{"known plus unknown entry, known hits", []feed.Affected{{Product: "docker-engine", Ranges: ranges}, {Product: "docker-engine"}}, "29.0.0", OutcomeAffected, ReasonInRange},
		{"known plus unknown entry, known misses", []feed.Affected{{Product: "docker-engine", Ranges: ranges}, {Product: "docker-engine"}}, "29.9.3", OutcomeUnknown, ReasonNoRanges},
		{"bad installed version", []feed.Affected{{Product: "docker-engine", Ranges: ranges}}, "latest", OutcomeUnknown, ReasonBadVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv := feed.Advisory{ID: "CVE-2026-115538", Affected: tt.affected}
			got := Check(SchemeSemver, tt.version, "docker-engine", adv)
			if got.Outcome != tt.outcome || got.Reason != tt.reason {
				t.Errorf("got %s/%s (%s), want %s/%s", got.Outcome, got.Reason, got.Detail, tt.outcome, tt.reason)
			}
		})
	}
}

func TestBranchDetailNamesTheFix(t *testing.T) {
	got := Evaluate(SchemePG, "17", []feed.Range{{Introduced: "17", Fixed: "17.12"}})
	if !got.Branch || !strings.Contains(got.Detail, "17.12") || !strings.Contains(got.Detail, "pull again") {
		t.Errorf("branch result = %+v", got)
	}
	if strings.ContainsAny(got.Detail, "\u2013\u2014") {
		t.Errorf("detail has a dash: %q", got.Detail)
	}
}
