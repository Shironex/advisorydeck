package engine

import (
	"time"

	"github.com/Shironex/advisorydeck/image/internal/feed"
	"github.com/Shironex/advisorydeck/image/internal/notify"
)

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// passesFloor reports whether an advisory's severity reaches the configured minimum.
// unknown (and any severity value this build does not know) never passes on its own.
func passesFloor(level, floor string) bool {
	return severityRank[level] > 0 && severityRank[level] >= severityRank[floor]
}

// EPSSUrgentPercentile is the EPSS percentile from which an advisory counts as likely to be
// exploited. Ingest uses the same threshold for the material revision, so crossing it is
// exactly one renotification.
const EPSSUrgentPercentile = 0.95

// urgency returns the bypass rule that makes an advisory post instantly whatever the
// severity floor and mode, or "".
//
// Only a KEV listing counts as KEV: an advisory the catalog was not checked for is not
// urgent (and is never shown as "not in KEV" either).
//
// The v1 feed has no explicit "action required" flag. Until it does, a reviewed note that
// says a default setup is exposed counts as a required action.
func urgency(a feed.Advisory) string {
	if a.KEV.State() == feed.KEVListed {
		return notify.UrgentKEV
	}
	if a.EPSS != nil && a.EPSS.Percentile >= EPSSUrgentPercentile {
		return notify.UrgentEPSS
	}
	if a.Note != nil && a.Note.Status == "reviewed" && a.Note.Exposure == "default-exposed" {
		return notify.UrgentActionRequired
	}
	return ""
}

// digestSlot returns the most recent digest time at or before now.
func digestSlot(now time.Time, clock string, loc *time.Location) time.Time {
	local := now.In(loc)
	hh := int(clock[0]-'0')*10 + int(clock[1]-'0')
	mm := int(clock[3]-'0')*10 + int(clock[4]-'0')
	slot := time.Date(local.Year(), local.Month(), local.Day(), hh, mm, 0, 0, loc)
	if slot.After(local) {
		slot = time.Date(local.Year(), local.Month(), local.Day()-1, hh, mm, 0, 0, loc)
	}
	return slot
}

// nextDigestSlot returns the first digest time strictly after now.
func nextDigestSlot(now time.Time, clock string, loc *time.Location) time.Time {
	s := digestSlot(now, clock, loc)
	return time.Date(s.Year(), s.Month(), s.Day()+1, s.Hour(), s.Minute(), 0, 0, loc)
}
