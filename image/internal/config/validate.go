package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the image runs from scratch, without system zoneinfo
)

// MinPollInterval is the shortest allowed poll interval.
const MinPollInterval = 5 * time.Minute

var (
	slugRe     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	versionRe  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$`)
	durationRe = regexp.MustCompile(`^([0-9]+)(s|m|h)$`)
	clockRe    = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	zoneRe     = regexp.MustCompile(`^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*$`)
	envNameRe  = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

	severities   = []string{"low", "medium", "high", "critical"}
	modes        = []string{"instant", "digest", "both"}
	channelTypes = []string{"discord", "slack", "webhook"}
)

// PollEvery returns the poll interval as a duration (Validate guarantees it parses).
func (c *Config) PollEvery() time.Duration {
	d, _ := parseDuration(c.Feed.PollInterval)
	return d
}

func parseDuration(s string) (time.Duration, bool) {
	m := durationRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour}[m[2]]
	return time.Duration(n) * unit, true
}

func oneOf(value string, allowed []string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	return false
}

// Validate reports every problem in the config, joined into one error.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Version != 1 {
		add("version: must be 1, got %d", c.Version)
	}

	if u, err := url.Parse(c.Feed.URL); err != nil || u.Scheme != "https" || u.Host == "" || !strings.HasSuffix(u.Path, "/api/v1/") {
		add("feed.url: must be an https URL ending in /api/v1/, got %q", c.Feed.URL)
	}
	if d, ok := parseDuration(c.Feed.PollInterval); !ok {
		add("feed.poll_interval: must look like 30m, got %q", c.Feed.PollInterval)
	} else if d < MinPollInterval {
		add("feed.poll_interval: must be at least 5m, got %q", c.Feed.PollInterval)
	}

	if len(c.Products) == 0 {
		add("products: list at least one product")
	}
	seen := map[string]bool{}
	for i, p := range c.Products {
		if !slugRe.MatchString(p.Slug) {
			add("products[%d].slug: %q is not a catalog slug", i, p.Slug)
		}
		if !versionRe.MatchString(string(p.Version)) || len(p.Version) > 64 {
			add("products[%d].version: %q is not a version or branch", i, p.Version)
		}
		if seen[p.Slug] {
			add("products: %s is listed more than once", p.Slug)
		}
		seen[p.Slug] = true
	}

	if !oneOf(c.MinSeverity, severities) {
		add("min_severity: must be one of %s, got %q", strings.Join(severities, ", "), c.MinSeverity)
	}
	if !oneOf(c.Mode, modes) {
		add("mode: must be one of %s, got %q", strings.Join(modes, ", "), c.Mode)
	}
	if !clockRe.MatchString(string(c.Digest.Time)) {
		add("digest.time: must be HH:MM, got %q", c.Digest.Time)
	}
	if !zoneRe.MatchString(c.Digest.Timezone) {
		add("digest.timezone: %q is not an IANA time zone", c.Digest.Timezone)
	} else if _, err := time.LoadLocation(c.Digest.Timezone); err != nil {
		add("digest.timezone: %q is not an IANA time zone", c.Digest.Timezone)
	}

	if len(c.Channels) == 0 {
		add("channels: list at least one channel")
	}
	for i, ch := range c.Channels {
		if !oneOf(ch.Type, channelTypes) {
			add("channels[%d].type: must be one of %s, got %q", i, strings.Join(channelTypes, ", "), ch.Type)
		}
		if !envNameRe.MatchString(ch.URLEnv) {
			add("channels[%d].url_env: must name an environment variable such as DISCORD_WEBHOOK_URL, got %q", i, ch.URLEnv)
		}
		if len(ch.Name) > 64 {
			add("channels[%d].name: at most 64 characters", i)
		}
	}

	if !strings.HasPrefix(c.StatePath, "/") {
		add("state_path: must be an absolute path, got %q", c.StatePath)
	}
	return errors.Join(errs...)
}
