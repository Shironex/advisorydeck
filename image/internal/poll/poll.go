// Package poll reads the published feed: the manifest with If-None-Match, then only the
// product files whose etag changed, each verified against the manifest etag (sha256 of
// the exact bytes) before it is trusted.
//
// Downloaded files are cached on the data volume, so a 304 still leaves every watched
// product available for matching and a restart does not download everything again.
package poll

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Shironex/advisorydeck/image/internal/feed"
	"github.com/Shironex/advisorydeck/image/internal/state"
)

// Size limits for downloaded documents.
const (
	MaxManifestBytes = 4 << 20
	MaxProductBytes  = 64 << 20
)

// Client polls one feed.
type Client struct {
	HTTP      *http.Client
	Base      string // feed base URL, ending in /api/v1/
	CacheDir  string // where manifest and product files are cached; empty disables caching
	UserAgent string
	Log       *slog.Logger
}

// Result is the outcome of one poll.
type Result struct {
	Manifest     *feed.Manifest
	ManifestETag string // HTTP ETag to send next time
	NotModified  bool
	// Products holds every watched product that is available, fresh or from the cache.
	Products map[string]*feed.ProductFeed
	// Fetched lists the products downloaded in this poll.
	Fetched []string
}

// Refresh polls the manifest and downloads changed product files for the watched slugs.
// A product that fails to download or verify is logged and skipped (its cached copy is
// still used); only a manifest failure is an error.
func (c *Client) Refresh(ctx context.Context, prevETag string, slugs []string) (*Result, error) {
	if c.CacheDir == "" {
		prevETag = ""
	} else if _, err := c.readCache("manifest.json"); err != nil {
		prevETag = "" // a 304 is useless without the cached body
	}
	body, etag, status, err := c.get(ctx, c.Base+"manifest.json", prevETag, MaxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	res := &Result{ManifestETag: etag, Products: map[string]*feed.ProductFeed{}}
	if status == http.StatusNotModified {
		res.NotModified = true
		res.ManifestETag = prevETag
		if body, err = c.readCache("manifest.json"); err != nil {
			return nil, fmt.Errorf("manifest: 304 but no cached copy: %w", err)
		}
	}
	m, err := feed.DecodeManifest(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	res.Manifest = m
	if !res.NotModified {
		c.writeCache("manifest.json", body)
	}

	for _, slug := range slugs {
		entry, ok := m.Products[slug]
		if !ok {
			c.Log.Warn("product is not in the feed manifest", "product", slug)
			continue
		}
		cacheName := filepath.Join("products", slug+".json")
		cached, _ := c.readCache(cacheName)
		if cached != nil && feed.ETag(cached) == entry.ETag {
			if p := c.decodeProduct(slug, cached); p != nil {
				res.Products[slug] = p
				continue
			}
		}
		fresh, err := c.fetchProduct(ctx, slug, entry.ETag)
		if err != nil {
			c.Log.Warn("product file not updated, will retry next poll", "product", slug, "err", err)
			if cached != nil {
				if p := c.decodeProduct(slug, cached); p != nil {
					res.Products[slug] = p
				}
			}
			continue
		}
		p := c.decodeProduct(slug, fresh)
		if p == nil {
			continue
		}
		c.writeCache(cacheName, fresh)
		res.Products[slug] = p
		res.Fetched = append(res.Fetched, slug)
	}
	return res, nil
}

func (c *Client) fetchProduct(ctx context.Context, slug, want string) ([]byte, error) {
	body, _, status, err := c.get(ctx, c.Base+"products/"+slug+".json", "", MaxProductBytes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", status)
	}
	if got := feed.ETag(body); got != want {
		return nil, fmt.Errorf("etag mismatch (file %s, manifest %s): probably caught mid-deploy", got, want)
	}
	return body, nil
}

func (c *Client) decodeProduct(slug string, raw []byte) *feed.ProductFeed {
	p, err := feed.DecodeProductFeed(bytes.NewReader(raw))
	if err != nil {
		c.Log.Warn("product file is invalid", "product", slug, "err", err)
		return nil
	}
	if p.Product.Slug != slug {
		c.Log.Warn("product file holds another product", "product", slug, "got", p.Product.Slug)
		return nil
	}
	return p
}

// get performs a GET and returns the body (for 200), the ETag header and the status.
func (c *Client) get(ctx context.Context, url, ifNoneMatch string, limit int64) ([]byte, string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, resp.Header.Get("ETag"), resp.StatusCode, nil
	case http.StatusOK:
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, "", resp.StatusCode, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", 0, err
	}
	if int64(len(body)) > limit {
		return nil, "", 0, fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return body, resp.Header.Get("ETag"), resp.StatusCode, nil
}

func (c *Client) readCache(name string) ([]byte, error) {
	if c.CacheDir == "" {
		return nil, fs.ErrNotExist
	}
	return os.ReadFile(filepath.Join(c.CacheDir, name)) // #nosec G304 -- name is a validated slug under our cache dir
}

func (c *Client) writeCache(name string, data []byte) {
	if c.CacheDir == "" {
		return
	}
	if err := state.WriteFileAtomic(filepath.Join(c.CacheDir, name), data); err != nil && !errors.Is(err, context.Canceled) {
		c.Log.Warn("could not cache feed file", "file", name, "err", err)
	}
}
