// Package testfeed serves the repository's feed fixtures from an httptest TLS server,
// with ETag and If-None-Match support, and fake webhook receivers, for tests only.
package testfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
)

// Feed is a fake feed host. Files maps a path below /api/v1/ to its bytes.
type Feed struct {
	Server *httptest.Server

	mu       sync.Mutex
	files    map[string][]byte
	requests map[string]int
	notMod   int
}

// NewFeed serves fixtures/api/v1 over TLS.
func NewFeed(t testing.TB) *Feed {
	t.Helper()
	f := &Feed{files: map[string][]byte{}, requests: map[string]int{}}
	for _, name := range []string{"manifest.json", "products/postgresql.json"} {
		raw, err := os.ReadFile(contracttest.Path(t, "fixtures/api/v1/"+name))
		if err != nil {
			t.Fatal(err)
		}
		f.files[name] = raw
	}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

// Base is the feed base URL, ending in /api/v1/.
func (f *Feed) Base() string { return f.Server.URL + "/api/v1/" }

// Set replaces one file.
func (f *Feed) Set(name string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[name] = data
}

// Get returns one file.
func (f *Feed) Get(name string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.files[name]
}

// Requests returns how many times a file was requested (any status).
func (f *Feed) Requests(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[name]
}

// NotModified returns how many 304 answers were sent.
func (f *Feed) NotModified() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.notMod
}

func (f *Feed) serve(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests[name]++
	data, ok := f.files[name]
	if !ok || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		f.notMod++
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// Hook is a fake webhook receiver. Respond decides each answer; the default is 204.
type Hook struct {
	Server *httptest.Server

	mu      sync.Mutex
	bodies  [][]byte
	Respond func(n int, w http.ResponseWriter) // n counts requests from 1
}

// NewHook starts a fake webhook over TLS.
func NewHook(t testing.TB) *Hook {
	t.Helper()
	h := &Hook{}
	h.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.bodies = append(h.bodies, body)
		n := len(h.bodies)
		respond := h.Respond
		h.mu.Unlock()
		if respond != nil {
			respond(n, w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(h.Server.Close)
	return h
}

// URL is the webhook URL (it carries a fake token, like real webhook URLs do).
func (h *Hook) URL() string { return h.Server.URL + "/hooks/fake-id/fake-token" }

// Bodies returns every request body received so far.
func (h *Hook) Bodies() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][]byte(nil), h.bodies...)
}

// SetProduct replaces products/<slug>.json and updates its etag in the manifest, like a
// new deploy of the feed.
func (f *Feed) SetProduct(t testing.TB, slug string, data []byte) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(f.Get("manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	products := m["products"].(map[string]any)
	entry, _ := products[slug].(map[string]any)
	if entry == nil {
		entry = map[string]any{"updated_at": "2026-11-14T09:00:00Z", "advisories": 1}
		products[slug] = entry
	}
	entry["etag"] = "sha256:" + hex.EncodeToString(sum[:])
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	f.Set("products/"+slug+".json", data)
	f.Set("manifest.json", raw)
}

// EditProduct decodes products/<slug>.json, lets edit change it, and publishes it.
func (f *Feed) EditProduct(t testing.TB, slug string, edit func(p map[string]any)) {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(f.Get("products/"+slug+".json"), &p); err != nil {
		t.Fatal(err)
	}
	edit(p)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	f.SetProduct(t, slug, raw)
}
