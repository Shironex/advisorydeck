package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Target is one configured webhook. URL is a secret and is never logged; logs name the
// channel by ID, Type, Name and URLEnv instead.
type Target struct {
	ID     string
	Type   string
	Name   string
	URLEnv string
	URL    string
}

// LogAttrs identifies a target in logs without its URL.
func (t Target) LogAttrs() []any {
	attrs := []any{"channel", t.ID, "type", t.Type, "url_env", t.URLEnv}
	if t.Name != "" {
		attrs = append(attrs, "name", t.Name)
	}
	return attrs
}

// Outcome is the result of posting one payload.
type Outcome int

// Outcomes.
const (
	// Sent: the webhook accepted the payload.
	Sent Outcome = iota
	// Dropped: the webhook refused this payload (400 and friends); retrying cannot help.
	Dropped
	// Disabled: the webhook is gone or the URL is wrong (401, 403, 404, 410). Do not
	// send anything else to it: Discord restricts IPs that keep hitting dead webhooks.
	Disabled
	// Failed: transient failures outlasted the retries; try again next cycle.
	Failed
)

func (o Outcome) String() string {
	return [...]string{"sent", "dropped", "disabled", "failed"}[o]
}

// Sender posts payloads. Rate-limit state is kept per target across calls.
type Sender struct {
	HTTP      *http.Client
	Log       *slog.Logger
	UserAgent string

	// MaxAttempts bounds attempts for one payload (429s included). Default 6.
	MaxAttempts int
	// BaseBackoff and MaxBackoff shape the exponential backoff on 5xx and network
	// errors. Defaults 2s and 2m.
	BaseBackoff, MaxBackoff time.Duration
	// MaxWait is the longest single wait for a rate limit; a longer retry_after gives up
	// until the next cycle. Default 10m.
	MaxWait time.Duration
	// Sleep waits or returns the context error. Tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error

	mu   sync.Mutex
	gate map[string]time.Time // earliest next request per target
}

func (s *Sender) defaults() {
	if s.MaxAttempts == 0 {
		s.MaxAttempts = 6
	}
	if s.BaseBackoff == 0 {
		s.BaseBackoff = 2 * time.Second
	}
	if s.MaxBackoff == 0 {
		s.MaxBackoff = 2 * time.Minute
	}
	if s.MaxWait == 0 {
		s.MaxWait = 10 * time.Minute
	}
	if s.Sleep == nil {
		s.Sleep = sleepCtx
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (s *Sender) waitGate(ctx context.Context, id string) error {
	s.mu.Lock()
	until := s.gate[id]
	s.mu.Unlock()
	d := time.Until(until)
	if d > s.MaxWait {
		return fmt.Errorf("rate limited for %s, longer than the %s limit", d.Round(time.Second), s.MaxWait)
	}
	return s.Sleep(ctx, d)
}

func (s *Sender) setGate(id string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gate == nil {
		s.gate = map[string]time.Time{}
	}
	if t := time.Now().Add(d); t.After(s.gate[id]) {
		s.gate[id] = t
	}
}

func (s *Sender) backoff(n int) time.Duration {
	d := s.BaseBackoff << (n - 1)
	if d > s.MaxBackoff || d <= 0 {
		d = s.MaxBackoff
	}
	return d/2 + rand.N(d/2+1) // #nosec G404 -- jitter, not security
}

// Post delivers one payload to a target, retrying as the target's answers allow. The
// returned status is the last HTTP status seen (0 for network errors).
func (s *Sender) Post(ctx context.Context, t Target, payload []byte) (Outcome, int, error) {
	s.defaults()
	var lastErr error
	status := 0
	for attempt := 1; attempt <= s.MaxAttempts; attempt++ {
		if err := s.waitGate(ctx, t.ID); err != nil {
			return Failed, status, err
		}
		resp, err := s.do(ctx, t, payload)
		if err != nil {
			if ctx.Err() != nil {
				return Failed, 0, ctx.Err()
			}
			lastErr, status = err, 0
			s.Log.Warn("webhook request failed, backing off", append(t.LogAttrs(), "attempt", attempt, "err", err)...)
			if err := s.Sleep(ctx, s.backoff(attempt)); err != nil {
				return Failed, 0, err
			}
			continue
		}
		status = resp.status
		s.applyRateHeaders(t.ID, resp.header)
		switch {
		case status >= 200 && status < 300:
			return Sent, status, nil
		case status == http.StatusTooManyRequests:
			wait := retryAfter(resp)
			lastErr = fmt.Errorf("rate limited (429), retry after %s", wait)
			s.Log.Warn("webhook rate limited", append(t.LogAttrs(), "retry_after", wait.String(), "attempt", attempt)...)
			s.setGate(t.ID, wait)
		case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusGone:
			return Disabled, status, fmt.Errorf("webhook answered %d", status)
		case status >= 400 && status < 500:
			return Dropped, status, fmt.Errorf("webhook refused the message (%d): %s", status, resp.snippet)
		default:
			lastErr = fmt.Errorf("webhook answered %d", status)
			s.Log.Warn("webhook server error, backing off", append(t.LogAttrs(), "status", status, "attempt", attempt)...)
			if err := s.Sleep(ctx, s.backoff(attempt)); err != nil {
				return Failed, status, err
			}
		}
	}
	return Failed, status, fmt.Errorf("gave up after %d attempts: %w", s.MaxAttempts, lastErr)
}

type response struct {
	status  int
	header  http.Header
	body    []byte
	snippet string
}

func (s *Sender) do(ctx context.Context, t Target, payload []byte) (*response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("cannot build the request (check the webhook URL)")
	}
	req.Header.Set("Content-Type", "application/json")
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, redact(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	return &response{status: resp.StatusCode, header: resp.Header, body: body, snippet: truncate(string(body), 200)}, nil
}

// redact drops the URL from an HTTP client error: webhook URLs carry their token.
func redact(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return fmt.Errorf("%s: %w", uerr.Op, uerr.Err)
	}
	return err
}

// applyRateHeaders honours Discord's bucket headers: when the bucket is empty, wait for
// it to reset before the next request.
func (s *Sender) applyRateHeaders(id string, h http.Header) {
	if h.Get("X-RateLimit-Remaining") != "0" {
		return
	}
	if secs, err := strconv.ParseFloat(h.Get("X-RateLimit-Reset-After"), 64); err == nil && secs > 0 {
		s.setGate(id, time.Duration(secs*float64(time.Second)))
	}
}

// retryAfter reads Discord's JSON retry_after (seconds, fractional) or the Retry-After
// header (seconds), defaulting to 5s.
func retryAfter(r *response) time.Duration {
	var body struct {
		RetryAfter float64 `json:"retry_after"`
	}
	if json.Unmarshal(r.body, &body) == nil && body.RetryAfter > 0 {
		return time.Duration(body.RetryAfter * float64(time.Second))
	}
	if secs, err := strconv.ParseFloat(r.header.Get("Retry-After"), 64); err == nil && secs > 0 {
		return time.Duration(secs * float64(time.Second))
	}
	return 5 * time.Second
}
