package engine

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/config"
	"github.com/Shironex/advisorydeck/image/internal/state"
)

// addAdvisory publishes a copy of the fixture advisory under a new id, affecting branch 17
// up to fix (and the other branches as in the fixture), with the given severity.
func (r *rig) addAdvisory(id, fix, level string, edit func(a map[string]any)) {
	r.t.Helper()
	r.feed.EditProduct(r.t, "postgresql", func(p map[string]any) {
		list := p["advisories"].([]any)
		var a map[string]any
		raw, _ := json.Marshal(list[len(list)-1])
		_ = json.Unmarshal(raw, &a)
		a["id"] = id
		a["revision"] = "sha256:" + strings.Repeat(string("abcdef0123456789"[len(list)%16]), 64)
		a["severity"].(map[string]any)["level"] = level
		a["note"] = nil
		a["affected"] = []any{map[string]any{"product": "postgresql", "ranges": []any{
			map[string]any{"introduced": "17", "fixed": fix},
		}}}
		if edit != nil {
			edit(a)
		}
		p["advisories"] = append(list, a)
	})
}

func (r *rig) setVersion(v string) {
	r.t.Helper()
	r.cfg.Products[0].Version = config.Text(v)
}

func (r *rig) lastBody() string {
	b := r.hook.Bodies()
	return string(b[len(b)-1])
}

func TestFirstStartSummaryThenOnlyNew(t *testing.T) {
	r := newRig(t, "instant", "medium")
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("first start sent %d, want 1 summary", n)
	}
	for _, want := range []string{"now watching 1 product", "Branch 17 has 1 open advisory at medium or above", "Make sure you run 17.12 or later"} {
		if !strings.Contains(r.lastBody(), want) {
			t.Errorf("summary lacks %q: %s", want, r.lastBody())
		}
	}
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("the summarized backlog was posted after all: %d", n)
	}

	// A new advisory fixed in the same release: one message for the release, the new one marked.
	r.addAdvisory("CVE-2026-999001", "17.12", "high", nil)
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("new advisory sent %d, want 1", n)
	}
	for _, want := range []string{"PostgreSQL 17.12 fixes 2 advisories for 17", "CVE-2026-999001 HIGH 4.3 (new)"} {
		if !strings.Contains(r.lastBody(), want) {
			t.Errorf("bundle lacks %q: %s", want, r.lastBody())
		}
	}
	st, err := state.Read(r.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if c := st.Channels["discord:DISCORD_WEBHOOK_URL:ops"]; c.Started.IsZero() || len(c.Instant) != 2 {
		t.Fatalf("channel state = %+v", c)
	}
}

func TestReplayBacklogFollowsTheSummary(t *testing.T) {
	r := newRig(t, "instant", "medium")
	r.addAdvisory("CVE-2026-999001", "17.12", "high", nil)
	r.addAdvisory("CVE-2026-999002", "17.10", "high", nil)
	e := r.engine(false, nil)
	e.ReplayBacklog = true
	if err := e.Cycle(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	// The summary, then one message for 17.12; 17.10 is covered by "run 17.12 or later".
	if n := r.newSends(); n != 2 {
		t.Fatalf("replay sent %d, want summary + one bundle", n)
	}
	if !strings.Contains(r.lastBody(), "PostgreSQL 17.12 fixes 2 advisories") || strings.Contains(r.lastBody(), "999002") {
		t.Errorf("bundle = %s", r.lastBody())
	}
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("resent %d", n)
	}
}

func TestBranchOlderReleaseIsCoveredByTheNewest(t *testing.T) {
	r := newRig(t, "instant", "medium")
	r.start()
	r.cycle(false) // the fixture advisory, fixed in 17.12
	r.newSends()
	r.addAdvisory("CVE-2026-999003", "17.13", "high", nil)
	r.addAdvisory("CVE-2026-999004", "17.11", "high", nil)
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("sent %d, want only the 17.13 release", n)
	}
	if body := r.lastBody(); !strings.Contains(body, "999003") || strings.Contains(body, "999004") || !strings.Contains(body, "17.13 or later") {
		t.Errorf("message = %s", body)
	}
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("the covered release was posted later: %d", n)
	}
	// An older release that turns up in CISA KEV is posted anyway.
	r.feed.EditProduct(t, "postgresql", func(p map[string]any) {
		for _, a := range p["advisories"].([]any) {
			m := a.(map[string]any)
			if m["id"] == "CVE-2026-999004" {
				m["kev"] = map[string]any{"listed": true, "added_at": "2026-11-16", "checked": true}
				m["revision"] = "sha256:" + strings.Repeat("9", 64)
			}
		}
	})
	r.cycle(false)
	if n := r.newSends(); n != 1 || !strings.Contains(r.lastBody(), "999004") || !strings.Contains(r.lastBody(), "[EXPLOITED]") {
		t.Fatalf("KEV on a covered release: %d sends, %s", n, r.lastBody())
	}
}

func TestExactVersionGroupsReleasesDueTogether(t *testing.T) {
	r := newRig(t, "instant", "medium")
	r.setVersion("17.4")
	r.start()
	r.addAdvisory("CVE-2026-999005", "17.11", "high", nil)
	r.addAdvisory("CVE-2026-999006", "17.13", "high", nil)
	r.cycle(false)
	// The fixture advisory (17.12) and the two new ones: three releases, one message.
	if n := r.newSends(); n != 1 {
		t.Fatalf("sent %d, want one group message", n)
	}
	for _, want := range []string{"3 releases fix 3 advisories for PostgreSQL 17.4", "Upgrade from 17.4 to 17.13 or later"} {
		if !strings.Contains(r.lastBody(), want) {
			t.Errorf("group lacks %q: %s", want, r.lastBody())
		}
	}
}

func TestExploitationSignals(t *testing.T) {
	r := newRig(t, "digest", "high")
	r.start()
	// A medium advisory whose KEV status was never checked is not urgent.
	r.addAdvisory("CVE-2026-999007", "17.12", "medium", func(a map[string]any) {
		a["kev"] = map[string]any{"listed": false, "added_at": nil, "checked": false}
	})
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("unchecked KEV went out: %d", n)
	}
	// A KEV listing is instant, even in digest mode and under the floor.
	r.addAdvisory("CVE-2026-999008", "17.12", "medium", func(a map[string]any) {
		a["kev"] = map[string]any{"listed": true, "added_at": "2026-11-16", "checked": true}
	})
	r.cycle(false)
	if n := r.newSends(); n != 1 || !strings.Contains(r.lastBody(), "999008") || !strings.Contains(r.lastBody(), "in CISA KEV") {
		t.Fatalf("KEV: %d sends: %s", n, r.lastBody())
	}
	// So is an EPSS score in the top five percent.
	r.addAdvisory("CVE-2026-999009", "17.12", "medium", func(a map[string]any) {
		a["epss"] = map[string]any{"score": 0.4, "percentile": 0.97, "date": "2026-11-16"}
	})
	r.cycle(false)
	if n := r.newSends(); n != 1 || !strings.Contains(r.lastBody(), "999009") {
		t.Fatalf("EPSS: %d sends: %s", n, r.lastBody())
	}
}

// A state file written by the previous image (version 1, every advisory sent one by one)
// moves forward without a summary and without resending anything.
func TestStateFromThePreviousImageResendsNothing(t *testing.T) {
	r := newRig(t, "instant", "medium")
	var p struct {
		Advisories []struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(r.feed.Get("products/postgresql.json"), &p); err != nil {
		t.Fatal(err)
	}
	v1 := `{"version":1,"channels":{"discord:DISCORD_WEBHOOK_URL:ops":{"instant":{"` + p.Advisories[0].ID + `|postgresql":"` + p.Advisories[0].Revision + `"},"digest":{},"last_digest":"2026-11-15T07:00:00Z"}}}`
	if err := os.WriteFile(r.cfg.StatePath, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	r.cycle(false)
	if n := r.newSends(); n != 0 {
		t.Fatalf("migrated state sent %d", n)
	}
	st, err := state.Read(r.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != state.Version {
		t.Fatalf("state version %d after a cycle", st.Version)
	}
	r.addAdvisory("CVE-2026-999010", "17.13", "high", nil)
	r.cycle(false)
	if n := r.newSends(); n != 1 {
		t.Fatalf("new advisory after migration sent %d, want 1", n)
	}
}
