// Package engine runs the daemon: poll the feed, match locally, apply the noise rules
// (severity floor, KEV, EPSS and action-required bypass, release bundles, the first-start
// summary, instant versus digest), and hand
// messages to the per-webhook queues, recording what was sent so it is sent only once.
package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/Shironex/advisorydeck/image/internal/config"
	"github.com/Shironex/advisorydeck/image/internal/feed"
	"github.com/Shironex/advisorydeck/image/internal/matching"
	"github.com/Shironex/advisorydeck/image/internal/notify"
	"github.com/Shironex/advisorydeck/image/internal/poll"
	"github.com/Shironex/advisorydeck/image/internal/state"
)

// StaleAfter is how old the feed's generated_at may be before a warning is logged.
const StaleAfter = 48 * time.Hour

// Engine holds everything one daemon needs.
type Engine struct {
	Cfg     *config.Config
	Poll    *poll.Client
	Matcher matching.Matcher
	Sender  *notify.Sender
	Targets []notify.Target
	Log     *slog.Logger
	// Store is what was sent. Nil means a fresh start that remembers nothing.
	Store *state.Store
	// DryRun prints what would be sent to Out instead of sending. The Store may be set
	// (read from disk) but is never saved.
	DryRun bool
	// ReplayBacklog posts the open advisories as bundles after the first-start summary,
	// instead of only summarizing them.
	ReplayBacklog bool
	Out           io.Writer
	// Now is the clock; tests replace it.
	Now func() time.Time
}

type channelPlan struct {
	target notify.Target
	// summary is set on a channel's first start: one overview instead of the backlog.
	summary *notify.Summary
	// instant holds, per product, the bundles to post now: one bundle is posted as it is,
	// several as one group message.
	instant []notify.ProductDigest
	digest  []notify.ProductDigest
	// silent are bundles a newer release already covers on a floating tag: recorded as
	// received without a post.
	silent []silentBundle
	due    bool
}

type silentBundle struct {
	items           []notify.Item
	instant, digest bool
}

// productMatch is everything matched for one watched product.
type productMatch struct {
	product    feed.ProductInfo
	declared   string
	branch     bool
	missing    bool
	advisories int
	// items affect the declared version (or are unknown) and pass the noise rules.
	items []notify.Item
	// latest is the newest fixing release among items: the one action to take.
	latest     string
	latestDate time.Time
	releases   int
	bundles    []notify.Bundle
}

// Cycle polls once, matches, and sends what is due. forceDigest sends the digest now
// whatever the clock says.
func (e *Engine) Cycle(ctx context.Context, forceDigest bool) error {
	now := e.Now()
	prevETag := ""
	if e.Store != nil && !e.DryRun {
		// A dry run has no feed cache, so it always downloads the manifest.
		e.Store.View(func(f *state.File) { prevETag = f.ManifestETag })
	}
	res, err := e.Poll.Refresh(ctx, prevETag, e.slugs())
	if err != nil {
		e.Log.Error("feed poll failed, will retry next cycle", "err", err)
		return err
	}
	e.Log.Info("feed polled", "not_modified", res.NotModified, "fetched", strings.Join(res.Fetched, ","), "products", len(res.Products))
	if age := now.Sub(res.Manifest.GeneratedAt); age > StaleAfter {
		e.Log.Warn("feed looks stale", "generated_at", res.Manifest.GeneratedAt, "age", age.Round(time.Hour).String())
	}
	if e.Store != nil && !e.DryRun {
		e.Store.Update(func(f *state.File) {
			f.ManifestETag = res.ManifestETag
			f.LastPollOK = now
		})
	}

	matches := e.match(res.Products)
	plans := e.plan(matches, now, forceDigest)
	if e.DryRun {
		e.report(plans, now)
		return nil
	}
	e.send(ctx, plans, now)
	return e.Store.Save()
}

func (e *Engine) slugs() []string {
	out := make([]string, 0, len(e.Cfg.Products))
	for _, p := range e.Cfg.Products {
		out = append(out, p.Slug)
	}
	return out
}

// match runs the matcher over every advisory of every watched product, keeps the ones that
// are affected or unknown and pass the noise rules, and bundles them by fixing release.
func (e *Engine) match(products map[string]*feed.ProductFeed) []productMatch {
	var out []productMatch
	for _, p := range e.Cfg.Products {
		pf := products[p.Slug]
		if pf == nil {
			out = append(out, productMatch{product: feed.ProductInfo{Slug: p.Slug, Name: p.Slug}, declared: string(p.Version), missing: true})
			continue
		}
		pm := productMatch{product: pf.Product, declared: string(p.Version), advisories: len(pf.Advisories)}
		declared := matching.Declared{Product: p.Slug, Version: string(p.Version)}
		counts := map[matching.Verdict]int{}
		for _, a := range pf.Advisories {
			r := e.Matcher.Match(declared, pf.Product, a)
			counts[r.Verdict]++
			if r.Branch {
				pm.branch = true
			}
			if r.Verdict != matching.Affected && r.Verdict != matching.Unknown {
				continue
			}
			urgent := urgency(a)
			if urgent == "" && !passesFloor(a.Severity.Level, e.Cfg.MinSeverity) {
				continue
			}
			pm.items = append(pm.items, notify.Item{
				Key: notify.Key(a.ID, p.Slug), Advisory: a, Product: pf.Product,
				Declared: string(p.Version), Verdict: r.Verdict, Reason: r.Reason, FixedIn: r.FixedIn, Branch: r.Branch, Urgent: urgent,
			})
		}
		sortItems(pm.items)
		pm.finish()
		e.Log.Info("matched", "product", p.Slug, "version", string(p.Version), "advisories", len(pf.Advisories),
			"affected", counts[matching.Affected], "unknown", counts[matching.Unknown], "not_affected", counts[matching.NotAffected],
			"notifiable", len(pm.items), "bundles", len(pm.bundles), "latest_fix", pm.latest)
		out = append(out, pm)
	}
	return out
}

// sortItems puts urgent items first, then the most severe, then the newest.
func sortItems(items []notify.Item) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i].Advisory, items[j].Advisory
		if (items[i].Urgent != "") != (items[j].Urgent != "") {
			return items[i].Urgent != ""
		}
		if severityRank[a.Severity.Level] != severityRank[b.Severity.Level] {
			return severityRank[a.Severity.Level] > severityRank[b.Severity.Level]
		}
		return a.PublishedAt.After(b.PublishedAt)
	})
}

// finish computes the latest fix and the bundles of a product's items.
func (pm *productMatch) finish() {
	scheme := pm.product.VersionScheme
	fixes := map[string]bool{}
	byKey := map[string]*notify.Bundle{}
	var keys []string
	for _, it := range pm.items {
		if it.FixedIn != "" {
			fixes[it.FixedIn] = true
			if c := matching.CompareVersions(scheme, it.FixedIn, pm.latest); pm.latest == "" || c > 0 {
				pm.latest, pm.latestDate = it.FixedIn, it.Advisory.PublishedAt
			} else if c == 0 && it.Advisory.PublishedAt.After(pm.latestDate) {
				pm.latestDate = it.Advisory.PublishedAt
			}
		}
		key := notify.BundleKey(pm.product.Slug, it.FixedIn, it.Advisory.ID)
		b := byKey[key]
		if b == nil {
			b = &notify.Bundle{Key: key, Product: pm.product, Declared: pm.declared, Branch: pm.branch, Fix: it.FixedIn}
			byKey[key] = b
			keys = append(keys, key)
		}
		b.Items = append(b.Items, it)
	}
	pm.releases = len(fixes)
	for _, k := range keys {
		b := byKey[k]
		b.Latest = pm.latest
		pm.bundles = append(pm.bundles, *b)
	}
	// Urgent bundles first, then the newest fix, then the most severe.
	sort.SliceStable(pm.bundles, func(i, j int) bool {
		a, b := pm.bundles[i], pm.bundles[j]
		if (a.Urgent() != "") != (b.Urgent() != "") {
			return a.Urgent() != ""
		}
		if a.Fix != b.Fix {
			if a.Fix == "" || b.Fix == "" {
				return a.Fix == ""
			}
			return matching.CompareVersions(scheme, a.Fix, b.Fix) > 0
		}
		return severityRank[a.Highest().Level] > severityRank[b.Highest().Level]
	})
}

func (e *Engine) summary(matches []productMatch) *notify.Summary {
	s := &notify.Summary{MinSeverity: e.Cfg.MinSeverity, Mode: e.Cfg.Mode, Backlog: e.ReplayBacklog}
	for _, pm := range matches {
		s.Products = append(s.Products, notify.ProductSummary{
			Product: pm.product, Declared: pm.declared, Branch: pm.branch, Missing: pm.missing,
			Advisories: pm.advisories, Items: pm.items, Latest: pm.latest, LatestDate: pm.latestDate, Releases: pm.releases,
		})
	}
	return s
}

// plan decides, per channel, what goes out: on a first start the summary (and, with the
// replay flag, the backlog), otherwise the bundles with something the channel has not
// received, instantly or in the digest.
func (e *Engine) plan(matches []productMatch, now time.Time, forceDigest bool) []channelPlan {
	loc, _ := time.LoadLocation(e.Cfg.Digest.Timezone) // validated with the config
	mode := e.Cfg.Mode
	var plans []channelPlan
	for _, t := range e.Targets {
		var ch state.Channel
		if e.Store != nil {
			e.Store.Update(func(f *state.File) {
				c := f.Channel(t.ID)
				if c.Disabled != nil && c.Disabled.Fingerprint != notify.Fingerprint(t.URL) {
					e.Log.Info("webhook URL changed, channel enabled again", t.LogAttrs()...)
					c.Disabled = nil
				}
				if c.LastDigest.IsZero() {
					c.LastDigest = now // the first digest comes at the next slot
				}
				ch = state.Channel{Instant: copyMap(c.Instant), Digest: copyMap(c.Digest), LastDigest: c.LastDigest, Started: c.Started, Disabled: c.Disabled}
			})
		} else {
			ch = state.Channel{Instant: map[string]string{}, Digest: map[string]string{}, LastDigest: now}
		}
		if ch.Disabled != nil {
			e.Log.Warn("webhook is disabled, skipping it", append(t.LogAttrs(), "status", ch.Disabled.Status, "since", ch.Disabled.At)...)
			continue
		}
		p := channelPlan{target: t}
		p.due = forceDigest || (mode != "instant" && ch.LastDigest.Before(digestSlot(now, string(e.Cfg.Digest.Time), loc)))
		if ch.Started.IsZero() {
			p.summary = e.summary(matches)
			if !e.ReplayBacklog {
				plans = append(plans, p)
				continue
			}
		}
		var digest []notify.ProductDigest
		for _, pm := range matches {
			pd := notify.ProductDigest{Product: pm.product, Declared: pm.declared, Branch: pm.branch, Latest: pm.latest}
			inst := pd
			for _, b := range pm.bundles {
				instantB, instantPending := pending(b, ch.Instant)
				digestB, digestPending := pending(b, ch.Digest)
				urgent := urgentPending(b, ch)
				instant := (mode == "instant" || mode == "both" || urgent) && instantPending
				inDigest := (mode == "both" || (mode == "digest" && !urgent)) && digestPending
				if !instant && !inDigest {
					continue
				}
				// On a floating tag, a release older than the newest fix is covered by the
				// action already posted ("run the latest or later"): record it, do not post.
				if pm.branch && !urgent && b.Fix != "" && matching.CompareVersions(pm.product.VersionScheme, b.Fix, pm.latest) < 0 {
					p.silent = append(p.silent, silentBundle{items: b.Items, instant: instant, digest: inDigest})
					continue
				}
				if instant {
					inst.Bundles = append(inst.Bundles, instantB)
				}
				if inDigest {
					pd.Bundles = append(pd.Bundles, digestB)
				}
			}
			if len(pd.Bundles) > 0 {
				digest = append(digest, pd)
			}
			if len(inst.Bundles) > 0 {
				p.instant = append(p.instant, inst)
			}
		}
		p.digest = digest
		plans = append(plans, p)
	}
	return plans
}

// pending returns the bundle with each item marked new or revised (when the channel received
// some of it before) and whether anything in it is not yet received at its revision.
func pending(b notify.Bundle, sent map[string]string) (notify.Bundle, bool) {
	out := b
	out.Items = make([]notify.Item, len(b.Items))
	changed, fresh := 0, 0
	for i, it := range b.Items {
		out.Items[i] = it
		switch prev := sent[it.Key]; {
		case prev == "":
			out.Items[i].Change = notify.ChangeNew
			changed++
			fresh++
		case prev != it.Advisory.Revision:
			out.Items[i].Change = notify.ChangeRevised
			changed++
		}
	}
	if fresh == len(b.Items) {
		// Everything is new: no marks needed.
		for i := range out.Items {
			out.Items[i].Change = ""
		}
	}
	return out, changed > 0
}

// urgentPending reports whether an item that bypasses the floor is not yet received.
func urgentPending(b notify.Bundle, ch state.Channel) bool {
	for _, it := range b.Items {
		if it.Urgent == "" {
			continue
		}
		if ch.Instant[it.Key] != it.Advisory.Revision {
			return true
		}
	}
	return false
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (e *Engine) send(ctx context.Context, plans []channelPlan, now time.Time) {
	var queues []notify.Queue
	digestJobs := map[string]int{}
	digestSent := map[string]int{}
	for _, p := range plans {
		r, err := notify.RendererFor(p.target.Type)
		if err != nil {
			e.Log.Error("cannot render", append(p.target.LogAttrs(), "err", err)...)
			continue
		}
		q := notify.Queue{Target: p.target}
		id := p.target.ID
		fp := notify.Fingerprint(p.target.URL)
		q.OnDisabled = func(status int) {
			e.Store.Update(func(f *state.File) {
				f.Channel(id).Disabled = &state.Disabled{Fingerprint: fp, Status: status, At: e.Now()}
			})
			e.save()
		}
		if p.summary != nil {
			msgs, err := r.Summary(*p.summary, now)
			if err != nil {
				e.Log.Error("cannot render the summary", append(p.target.LogAttrs(), "err", err)...)
				continue
			}
			for _, m := range msgs {
				q.Jobs = append(q.Jobs, notify.Job{Message: m, OnSent: e.recordSummary(id, m.Items, now)})
			}
		}
		if len(p.silent) > 0 {
			e.Store.Update(func(f *state.File) {
				c := f.Channel(id)
				for _, sb := range p.silent {
					for _, it := range sb.items {
						if sb.instant {
							c.Instant[it.Key] = it.Advisory.Revision
						}
						if sb.digest {
							c.Digest[it.Key] = it.Advisory.Revision
						}
					}
				}
			})
		}
		for _, d := range p.instant {
			var msgs []notify.Message
			var err error
			if len(d.Bundles) == 1 {
				msgs, err = r.Bundle(d.Bundles[0], now)
			} else {
				msgs, err = r.Group(d, now)
			}
			if err != nil {
				e.Log.Error("cannot render", append(p.target.LogAttrs(), "product", d.Product.Slug, "err", err)...)
				continue
			}
			for _, m := range msgs {
				q.Jobs = append(q.Jobs, notify.Job{Message: m, OnSent: e.record(id, m.Items, false, nil)})
			}
		}
		if p.due && len(p.digest) > 0 {
			msgs, err := r.Digest(p.digest, now)
			if err != nil {
				e.Log.Error("cannot render the digest", append(p.target.LogAttrs(), "err", err)...)
			}
			digestJobs[id] = len(msgs)
			for _, m := range msgs {
				q.Jobs = append(q.Jobs, notify.Job{Message: m, OnSent: e.record(id, m.Items, true, func() { digestSent[id]++ })})
			}
		} else if p.due {
			digestJobs[id] = 0
		}
		queues = append(queues, q)
	}
	e.Sender.Dispatch(ctx, queues)
	// A digest slot counts as handled only when every part of it went out.
	e.Store.Update(func(f *state.File) {
		for id, n := range digestJobs {
			if digestSent[id] == n {
				f.Channel(id).LastDigest = now
			}
		}
	})
}

// record returns the callback that marks items as sent on one channel and saves the
// state at once, so a crash right after a send never causes a resend.
func (e *Engine) record(channelID string, items []notify.Item, digest bool, extra func()) func() {
	return func() {
		e.Store.Update(func(f *state.File) {
			c := f.Channel(channelID)
			for _, it := range items {
				if digest {
					c.Digest[it.Key] = it.Advisory.Revision
				} else {
					c.Instant[it.Key] = it.Advisory.Revision
				}
			}
			if extra != nil {
				extra() // runs under the store lock, so counters need no lock of their own
			}
		})
		e.save()
	}
}

// recordSummary marks the channel as started and everything the summary covered as
// received, for instant posts and digests alike, so none of it is posted again.
func (e *Engine) recordSummary(channelID string, items []notify.Item, now time.Time) func() {
	return func() {
		e.Store.Update(func(f *state.File) {
			c := f.Channel(channelID)
			for _, it := range items {
				c.Instant[it.Key] = it.Advisory.Revision
				c.Digest[it.Key] = it.Advisory.Revision
			}
			c.Started = now
		})
		e.save()
	}
}

func (e *Engine) save() {
	if err := e.Store.Save(); err != nil {
		e.Log.Error("cannot save state", "path", e.Store.Path(), "err", err)
	}
}

func (e *Engine) report(plans []channelPlan, now time.Time) {
	loc, _ := time.LoadLocation(e.Cfg.Digest.Timezone)
	fmt.Fprintf(e.Out, "dry run: nothing is sent and no state is written\n")
	for _, p := range plans {
		fmt.Fprintf(e.Out, "\nchannel %s\n", p.target.ID)
		if s := p.summary; s != nil {
			fmt.Fprintf(e.Out, "  first start: 1 summary message instead of the backlog")
			if s.Backlog {
				fmt.Fprintf(e.Out, " (the backlog follows: -replay-backlog)")
			}
			fmt.Fprintln(e.Out)
			for _, ps := range s.Products {
				fmt.Fprintf(e.Out, "    %s %s: %s\n", ps.Product.Slug, ps.Declared, notify.SummaryLine(ps))
			}
		}
		fmt.Fprintf(e.Out, "  instant: %d\n", len(p.instant))
		for _, d := range p.instant {
			if len(d.Bundles) > 1 {
				fmt.Fprintf(e.Out, "    %s %s: one message for %d releases\n", d.Product.Slug, d.Declared, len(d.Bundles))
			}
			for _, b := range d.Bundles {
				fmt.Fprintf(e.Out, "    %s: %d advisories%s\n", b.Key, len(b.Items), urgentNote(b))
				for _, it := range b.Items {
					fmt.Fprintf(e.Out, "      %s  [%s] %s %s (%s)\n", it.Advisory.ID, it.Advisory.Severity.Level, it.Product.Slug, it.Declared, it.Reason)
				}
			}
		}
		if len(p.silent) > 0 {
			fmt.Fprintf(e.Out, "  covered by a newer fix, recorded without a post: %d\n", len(p.silent))
		}
		if e.Cfg.Mode != "instant" {
			n := 0
			for _, d := range p.digest {
				n += len(d.Bundles)
			}
			fmt.Fprintf(e.Out, "  digest: %d (next at %s)\n", n, nextDigestSlot(now, string(e.Cfg.Digest.Time), loc).Format(time.RFC3339))
			for _, d := range p.digest {
				for _, b := range d.Bundles {
					fmt.Fprintf(e.Out, "    %s: %d advisories\n", b.Key, len(b.Items))
					for _, it := range b.Items {
						fmt.Fprintf(e.Out, "      %s  [%s] %s %s (%s)\n", it.Advisory.ID, it.Advisory.Severity.Level, it.Product.Slug, it.Declared, it.Reason)
					}
				}
			}
		}
	}
}

func urgentNote(b notify.Bundle) string {
	if u := b.Urgent(); u != "" {
		return ", posted instantly: " + u
	}
	return ""
}

// Run polls until the context ends: every poll interval (with up to 10% jitter) and at
// each digest time.
func (e *Engine) Run(ctx context.Context) error {
	every := e.Cfg.PollEvery()
	loc, _ := time.LoadLocation(e.Cfg.Digest.Timezone)
	e.Log.Info("advisorydeck started", "products", len(e.Cfg.Products), "channels", len(e.Targets),
		"mode", e.Cfg.Mode, "min_severity", e.Cfg.MinSeverity, "poll_interval", every.String())
	for {
		_ = e.Cycle(ctx, false) // errors are logged; the next cycle retries
		if ctx.Err() != nil {
			return nil
		}
		now := e.Now()
		wait := every + rand.N(every/10+1) // #nosec G404 -- jitter, not security
		if e.Cfg.Mode != "instant" {
			if d := nextDigestSlot(now, string(e.Cfg.Digest.Time), loc).Sub(now) + time.Second; d < wait {
				wait = d
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			e.Log.Info("advisorydeck stopping")
			return nil
		case <-t.C:
		}
	}
}
