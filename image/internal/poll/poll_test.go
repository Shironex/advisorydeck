package poll

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/testfeed"
)

func newClient(f *testfeed.Feed, cache string) *Client {
	return &Client{HTTP: f.Server.Client(), Base: f.Base(), CacheDir: cache, UserAgent: "advisorydeck/test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestRefreshETagsAndCache(t *testing.T) {
	f := testfeed.NewFeed(t)
	cache := filepath.Join(t.TempDir(), "feeds")
	c := newClient(f, cache)
	ctx := context.Background()

	first, err := c.Refresh(ctx, "", []string{"postgresql", "traefik"})
	if err != nil {
		t.Fatal(err)
	}
	if first.NotModified || first.ManifestETag == "" || len(first.Fetched) != 1 || first.Products["postgresql"] == nil {
		t.Fatalf("first = %+v", first)
	}
	if _, ok := first.Products["traefik"]; ok {
		t.Fatal("traefik is not in the fixture manifest")
	}

	second, err := c.Refresh(ctx, first.ManifestETag, []string{"postgresql"})
	if err != nil {
		t.Fatal(err)
	}
	if !second.NotModified || len(second.Fetched) != 0 || second.Products["postgresql"] == nil {
		t.Fatalf("second = %+v", second)
	}
	if f.NotModified() != 1 || f.Requests("products/postgresql.json") != 1 {
		t.Fatalf("304s %d, product requests %d", f.NotModified(), f.Requests("products/postgresql.json"))
	}

	// A fresh client with the same cache still has the product after a 304.
	third, err := newClient(f, cache).Refresh(ctx, first.ManifestETag, []string{"postgresql"})
	if err != nil || third.Products["postgresql"] == nil || f.Requests("products/postgresql.json") != 1 {
		t.Fatalf("third = %+v, %v", third, err)
	}
}

func TestRefreshRejectsEtagMismatch(t *testing.T) {
	f := testfeed.NewFeed(t)
	orig := f.Get("products/postgresql.json")
	f.Set("products/postgresql.json", append(append([]byte(nil), orig...), ' '))
	c := newClient(f, "")
	res, err := c.Refresh(context.Background(), "", []string{"postgresql"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Products["postgresql"] != nil || len(res.Fetched) != 0 {
		t.Fatalf("mismatched file was accepted: %+v", res)
	}
	// Next poll, the deploy finished: the file matches again.
	f.Set("products/postgresql.json", orig)
	res, err = c.Refresh(context.Background(), "", []string{"postgresql"})
	if err != nil || res.Products["postgresql"] == nil {
		t.Fatalf("after fix: %+v %v", res, err)
	}
}

func TestRefreshManifestErrors(t *testing.T) {
	f := testfeed.NewFeed(t)
	f.Set("manifest.json", []byte(`{"schema":"advisorydeck/v9/manifest"}`))
	if _, err := newClient(f, "").Refresh(context.Background(), "", []string{"postgresql"}); err == nil {
		t.Fatal("unknown schema marker accepted")
	}
	f.Set("manifest.json", nil)
	f2 := testfeed.NewFeed(t)
	f2.Server.Close()
	if _, err := newClient(f2, "").Refresh(context.Background(), "", nil); err == nil {
		t.Fatal("closed server gave no error")
	}
}
