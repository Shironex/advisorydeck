// Command advisorydeck is the Advisorydeck notifier image: it polls the published
// advisory feed, matches it locally against the products in its config, and posts what
// affects them to Discord, Slack or a generic JSON webhook.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Shironex/advisorydeck/image/internal/config"
	"github.com/Shironex/advisorydeck/image/internal/engine"
	"github.com/Shironex/advisorydeck/image/internal/matching"
	"github.com/Shironex/advisorydeck/image/internal/notify"
	"github.com/Shironex/advisorydeck/image/internal/poll"
	"github.com/Shironex/advisorydeck/image/internal/state"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Usage:
  advisorydeck run [-config path]                       poll and notify until stopped
  advisorydeck once [-config path] [-dry-run] [-digest-now]
                                                        poll and notify once, then exit
  advisorydeck healthcheck [-config path]               exit 0 when the last poll is recent
  advisorydeck check-config [-config path]              validate a config file
  advisorydeck version                                  print the version

The config file defaults to %s. Webhook URLs come from the environment
variables the config names (url_env), never from the file.
`

// env holds what the commands take from the process, so tests can replace it.
type env struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	httpClient     *http.Client
	now            func() time.Time
	ctx            context.Context
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e := env{
		stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		now:        time.Now, ctx: ctx,
	}
	os.Exit(run(os.Args[1:], e))
}

func run(args []string, e env) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, usage, config.DefaultPath)
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(e.stderr)
	path := flags.String("config", config.DefaultPath, "config file")
	switch args[0] {
	case "version":
		fmt.Fprintln(e.stdout, version)
		return 0
	case "check-config":
		if flags.Parse(args[1:]) != nil {
			return 2
		}
		cfg, err := config.Load(*path)
		if err != nil {
			fmt.Fprintf(e.stderr, "%s: %v\n", *path, err)
			return 1
		}
		fmt.Fprintf(e.stdout, "%s: ok (%d products, %d channels, mode %s, min severity %s)\n",
			*path, len(cfg.Products), len(cfg.Channels), cfg.Mode, cfg.MinSeverity)
		return 0
	case "healthcheck":
		if flags.Parse(args[1:]) != nil {
			return 2
		}
		return healthcheck(*path, e)
	case "run", "once":
		dry := flags.Bool("dry-run", false, "print what would be sent; send nothing, write nothing (once only)")
		digestNow := flags.Bool("digest-now", false, "send the digest now instead of at its time (once only)")
		if flags.Parse(args[1:]) != nil {
			return 2
		}
		if args[0] == "run" && (*dry || *digestNow) {
			fmt.Fprintln(e.stderr, "-dry-run and -digest-now only work with once")
			return 2
		}
		return daemon(args[0] == "once", *path, *dry, *digestNow, e)
	default:
		fmt.Fprintf(e.stderr, "unknown command %q\n", args[0])
		fmt.Fprintf(e.stderr, usage, config.DefaultPath)
		return 2
	}
}

func newLogger(w io.Writer, getenv func(string) string) *slog.Logger {
	level := slog.LevelInfo
	if strings.EqualFold(getenv("ADVISORYDECK_LOG_LEVEL"), "debug") {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// targets resolves each channel's webhook URL from the environment. In a dry run the
// URLs are not needed and may be missing.
func targets(cfg *config.Config, getenv func(string) string, dry bool) ([]notify.Target, error) {
	var out []notify.Target
	var errs []error
	for _, ch := range cfg.Channels {
		t := notify.Target{ID: ch.Type + ":" + ch.URLEnv + ":" + ch.Name, Type: ch.Type, Name: ch.Name, URLEnv: ch.URLEnv, URL: strings.TrimSpace(getenv(ch.URLEnv))}
		if !dry {
			if t.URL == "" {
				errs = append(errs, fmt.Errorf("environment variable %s is not set (webhook for the %s channel)", ch.URLEnv, ch.Type))
			} else if err := notify.ValidateURL(ch.Type, t.URL); err != nil {
				errs = append(errs, fmt.Errorf("environment variable %s: %w", ch.URLEnv, err))
			}
		}
		out = append(out, t)
	}
	return out, errors.Join(errs...)
}

func daemon(once bool, path string, dry, digestNow bool, e env) int {
	log := newLogger(e.stderr, e.getenv)
	cfg, err := config.Load(path)
	if err != nil {
		log.Error("invalid config", "path", path, "err", err)
		return 1
	}
	ts, err := targets(cfg, e.getenv, dry)
	if err != nil {
		log.Error("webhook configuration", "err", err)
		return 1
	}
	ua := "advisorydeck/" + version
	eng := &engine.Engine{
		Cfg:     cfg,
		Poll:    &poll.Client{HTTP: e.httpClient, Base: cfg.Feed.URL, UserAgent: ua, Log: log},
		Matcher: matching.Library{},
		Sender:  &notify.Sender{HTTP: e.httpClient, Log: log, UserAgent: ua},
		Targets: ts,
		Log:     log,
		DryRun:  dry,
		Out:     e.stdout,
		Now:     e.now,
	}
	if !dry {
		st, err := state.Open(cfg.StatePath)
		if err != nil {
			log.Error("cannot read state", "path", cfg.StatePath, "err", err)
			return 1
		}
		eng.Store = st
		eng.Poll.CacheDir = filepath.Join(filepath.Dir(cfg.StatePath), "feeds")
		// Fail early, with a clear message, when the data volume is not writable.
		if err := st.Save(); err != nil {
			log.Error("state is not writable: mount a writable volume at the state folder", "path", cfg.StatePath, "err", err)
			return 1
		}
	}
	if !once {
		if err := eng.Run(e.ctx); err != nil {
			log.Error("stopped", "err", err)
			return 1
		}
		return 0
	}
	if err := eng.Cycle(e.ctx, digestNow); err != nil {
		return 1
	}
	return 0
}

// healthcheck passes when the last successful poll is recent: within three poll
// intervals plus five minutes.
func healthcheck(path string, e env) int {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(e.stderr, "unhealthy: config %s: %v\n", path, err)
		return 1
	}
	st, err := state.Read(cfg.StatePath)
	if err != nil {
		fmt.Fprintf(e.stderr, "unhealthy: %v\n", err)
		return 1
	}
	if st.LastPollOK.IsZero() {
		fmt.Fprintln(e.stderr, "unhealthy: no successful poll yet")
		return 1
	}
	limit := 3*cfg.PollEvery() + 5*time.Minute
	if age := e.now().Sub(st.LastPollOK); age > limit {
		fmt.Fprintf(e.stderr, "unhealthy: last successful poll %s ago (limit %s)\n", age.Round(time.Second), limit)
		return 1
	}
	fmt.Fprintf(e.stdout, "ok: last successful poll at %s\n", st.LastPollOK.UTC().Format(time.RFC3339))
	return 0
}
