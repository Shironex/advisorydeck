// Package engine runs the daemon: poll the feed, match locally, apply the noise rules
// (severity floor, KEV and action-required bypass, instant versus digest), and hand
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
	// Store is nil in dry-run mode: nothing is remembered.
	Store *state.Store
	// DryRun prints what would be sent to Out instead of sending.
	DryRun bool
	Out    io.Writer
	// Now is the clock; tests replace it.
	Now func() time.Time
}

type channelPlan struct {
	target  notify.Target
	instant []notify.Item
	digest  []notify.Item
	due     bool
}

// Cycle polls once, matches, and sends what is due. forceDigest sends the digest now
// whatever the clock says.
func (e *Engine) Cycle(ctx context.Context, forceDigest bool) error {
	now := e.Now()
	prevETag := ""
	if e.Store != nil {
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
	if e.Store != nil {
		e.Store.Update(func(f *state.File) {
			f.ManifestETag = res.ManifestETag
			f.LastPollOK = now
		})
	}

	items := e.match(res.Products)
	plans := e.plan(items, now, forceDigest)
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

// match runs the matcher over every advisory of every watched product and keeps the
// ones that are affected or unknown and pass the noise rules.
func (e *Engine) match(products map[string]*feed.ProductFeed) []notify.Item {
	var items []notify.Item
	for _, p := range e.Cfg.Products {
		pf := products[p.Slug]
		if pf == nil {
			continue
		}
		declared := matching.Declared{Product: p.Slug, Version: string(p.Version)}
		counts := map[matching.Verdict]int{}
		for _, a := range pf.Advisories {
			r := e.Matcher.Match(declared, pf.Product, a)
			counts[r.Verdict]++
			if r.Verdict != matching.Affected && r.Verdict != matching.Unknown {
				continue
			}
			urgent := urgency(a)
			if urgent == "" && !passesFloor(a.Severity.Level, e.Cfg.MinSeverity) {
				continue
			}
			items = append(items, notify.Item{
				Key: notify.Key(a.ID, p.Slug), Advisory: a, Product: pf.Product,
				Declared: string(p.Version), Verdict: r.Verdict, Reason: r.Reason, FixedIn: r.FixedIn, Urgent: urgent,
			})
		}
		e.Log.Info("matched", "product", p.Slug, "version", string(p.Version), "advisories", len(pf.Advisories),
			"affected", counts[matching.Affected], "unknown", counts[matching.Unknown], "not_affected", counts[matching.NotAffected])
	}
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
	return items
}

// plan decides, per channel, what goes out instantly and what waits for the digest,
// leaving out revisions that channel already received.
func (e *Engine) plan(items []notify.Item, now time.Time, forceDigest bool) []channelPlan {
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
				ch = state.Channel{Instant: copyMap(c.Instant), Digest: copyMap(c.Digest), LastDigest: c.LastDigest, Disabled: c.Disabled}
			})
		}
		if ch.Disabled != nil {
			e.Log.Warn("webhook is disabled, skipping it", append(t.LogAttrs(), "status", ch.Disabled.Status, "since", ch.Disabled.At)...)
			continue
		}
		p := channelPlan{target: t}
		for _, it := range items {
			rev := it.Advisory.Revision
			instant := mode == "instant" || mode == "both" || it.Urgent != ""
			inDigest := mode == "both" || (mode == "digest" && it.Urgent == "")
			if instant && ch.Instant[it.Key] != rev {
				p.instant = append(p.instant, it)
			}
			if inDigest && ch.Digest[it.Key] != rev {
				p.digest = append(p.digest, it)
			}
		}
		p.due = forceDigest || (mode != "instant" && ch.LastDigest.Before(digestSlot(now, string(e.Cfg.Digest.Time), loc)))
		plans = append(plans, p)
	}
	return plans
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
		for _, it := range p.instant {
			msgs, err := r.Render([]notify.Item{it}, notify.Instant, now)
			if err != nil {
				e.Log.Error("cannot render", append(p.target.LogAttrs(), "advisory", it.Advisory.ID, "err", err)...)
				continue
			}
			for _, m := range msgs {
				q.Jobs = append(q.Jobs, notify.Job{Message: m, OnSent: e.record(id, m.Items, false, nil)})
			}
		}
		if p.due && len(p.digest) > 0 {
			msgs, err := r.Render(p.digest, notify.Digest, now)
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

func (e *Engine) save() {
	if err := e.Store.Save(); err != nil {
		e.Log.Error("cannot save state", "path", e.Store.Path(), "err", err)
	}
}

func (e *Engine) report(plans []channelPlan, now time.Time) {
	loc, _ := time.LoadLocation(e.Cfg.Digest.Timezone)
	fmt.Fprintf(e.Out, "dry run: nothing is sent and no state is written\n")
	for _, p := range plans {
		name := p.target.ID
		fmt.Fprintf(e.Out, "\nchannel %s\n", name)
		fmt.Fprintf(e.Out, "  instant: %d\n", len(p.instant))
		for _, it := range p.instant {
			fmt.Fprintf(e.Out, "    %s  [%s] %s %s (%s)%s\n", it.Advisory.ID, it.Advisory.Severity.Level, it.Product.Slug, it.Declared, it.Reason, urgentNote(it))
		}
		if e.Cfg.Mode != "instant" {
			fmt.Fprintf(e.Out, "  digest: %d (next at %s)\n", len(p.digest), nextDigestSlot(now, string(e.Cfg.Digest.Time), loc).Format(time.RFC3339))
			for _, it := range p.digest {
				fmt.Fprintf(e.Out, "    %s  [%s] %s %s (%s)\n", it.Advisory.ID, it.Advisory.Severity.Level, it.Product.Slug, it.Declared, it.Reason)
			}
		}
	}
}

func urgentNote(it notify.Item) string {
	if it.Urgent == "" {
		return ""
	}
	return ", posted instantly: " + it.Urgent
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
