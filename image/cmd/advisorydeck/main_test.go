package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
	"github.com/Shironex/advisorydeck/image/internal/testfeed"
)

type harness struct {
	feed   *testfeed.Feed
	hook   *testfeed.Hook
	dir    string
	config string
	envs   map[string]string
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	h := &harness{feed: testfeed.NewFeed(t), hook: testfeed.NewHook(t), dir: t.TempDir(), now: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	h.envs = map[string]string{"DISCORD_WEBHOOK_URL": h.hook.URL()}
	h.config = filepath.Join(h.dir, "advisorydeck.yml")
	yml := fmt.Sprintf(`version: 1
feed:
  url: %s
products:
  - slug: postgresql
    version: '17.4'
min_severity: medium
mode: instant
channels:
  - type: discord
    url_env: DISCORD_WEBHOOK_URL
state_path: %s
`, h.feed.Base(), filepath.ToSlash(filepath.Join(h.dir, "data", "state.json")))
	if err := os.WriteFile(h.config, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) run(ctx context.Context, args ...string) (int, string, string) {
	client := h.feed.Server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(h.hook.Server.Certificate())
	var stdout, stderr bytes.Buffer
	code := run(args, env{
		stdout: &stdout, stderr: &stderr,
		getenv:     func(k string) string { return h.envs[k] },
		httpClient: client,
		now:        func() time.Time { return h.now },
		ctx:        ctx,
	})
	return code, stdout.String(), stderr.String()
}

func TestRun(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"no args", nil, 2, "Usage"},
		{"unknown", []string{"serve"}, 2, "unknown command"},
		{"version", []string{"version"}, 0, "dev"},
		{"valid config", []string{"check-config", "-config", contracttest.Path(t, "fixtures/image/advisorydeck.yml")}, 0, "ok (3 products, 2 channels, mode digest, min severity high)"},
		{"invalid config", []string{"check-config", "-config", contracttest.Path(t, "fixtures/image/invalid/unknown-severity.yml")}, 1, "min_severity"},
		{"dry-run needs once", []string{"run", "-dry-run"}, 2, "only work with once"},
	}
	h := newHarness(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := h.run(context.Background(), tc.args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d (stderr %q)", code, tc.code, stderr)
			}
			if got := stdout + stderr; !strings.Contains(got, tc.out) {
				t.Fatalf("output %q does not contain %q", got, tc.out)
			}
		})
	}
}

func TestOnceDryRun(t *testing.T) {
	h := newHarness(t)
	h.envs = map[string]string{} // a dry run needs no webhook URLs
	code, stdout, stderr := h.run(context.Background(), "once", "-dry-run", "-config", h.config)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "instant: 1") || !strings.Contains(stdout, "17.4 is affected; fixed in 17.12") {
		t.Fatalf("stdout = %s", stdout)
	}
	if len(h.hook.Bodies()) != 0 {
		t.Fatal("dry run posted")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "data")); !os.IsNotExist(err) {
		t.Fatal("dry run wrote to the data folder")
	}
}

func TestOnceSendsAndHealthcheck(t *testing.T) {
	h := newHarness(t)
	if code, _, stderr := h.run(context.Background(), "healthcheck", "-config", h.config); code != 1 || !strings.Contains(stderr, "no successful poll") {
		t.Fatalf("healthcheck before any poll: %d %s", code, stderr)
	}
	code, _, stderr := h.run(context.Background(), "once", "-config", h.config)
	if code != 0 || len(h.hook.Bodies()) != 1 {
		t.Fatalf("exit %d, %d posts: %s", code, len(h.hook.Bodies()), stderr)
	}
	if strings.Contains(stderr, "fake-token") {
		t.Fatal("logs leak the webhook URL")
	}
	if !strings.Contains(stderr, `"msg":"notification sent"`) {
		t.Fatalf("no structured log line: %s", stderr)
	}
	if code, _, _ := h.run(context.Background(), "once", "-config", h.config); code != 0 || len(h.hook.Bodies()) != 1 {
		t.Fatalf("second once resent: %d posts", len(h.hook.Bodies()))
	}
	if code, stdout, stderr := h.run(context.Background(), "healthcheck", "-config", h.config); code != 0 || !strings.Contains(stdout, "ok") {
		t.Fatalf("healthcheck after a poll: %d %s", code, stderr)
	}
	h.now = h.now.Add(3 * time.Hour)
	if code, _, stderr := h.run(context.Background(), "healthcheck", "-config", h.config); code != 1 || !strings.Contains(stderr, "unhealthy") {
		t.Fatalf("healthcheck after 3h: %d %s", code, stderr)
	}
}

func TestOnceMissingWebhookEnv(t *testing.T) {
	h := newHarness(t)
	h.envs = map[string]string{}
	code, _, stderr := h.run(context.Background(), "once", "-config", h.config)
	if code != 1 || !strings.Contains(stderr, "DISCORD_WEBHOOK_URL is not set") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	h.envs = map[string]string{"DISCORD_WEBHOOK_URL": "http://webhooks.example.invalid/plain-http"}
	code, _, stderr = h.run(context.Background(), "once", "-config", h.config)
	if code != 1 || !strings.Contains(stderr, "https://") || strings.Contains(stderr, "plain-http") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

func TestRunStopsOnSignal(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		code, _, _ := h.run(ctx, "run", "-config", h.config)
		done <- code
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.hook.Bodies()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 || len(h.hook.Bodies()) != 1 {
			t.Fatalf("exit %d, %d posts", code, len(h.hook.Bodies()))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
}
