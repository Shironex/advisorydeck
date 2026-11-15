package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
)

func TestLoadFullFixture(t *testing.T) {
	cfg, err := Load(contracttest.Path(t, "fixtures/image/advisorydeck.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Products); got != 3 {
		t.Fatalf("products = %d, want 3", got)
	}
	if cfg.Products[0].Slug != "postgresql" || cfg.Products[0].Version != "17" {
		t.Errorf("first product = %+v", cfg.Products[0])
	}
	if cfg.PollEvery() != 30*time.Minute {
		t.Errorf("poll = %v", cfg.PollEvery())
	}
	if cfg.Channels[0].URLEnv != "DISCORD_WEBHOOK_URL" {
		t.Errorf("channel = %+v", cfg.Channels[0])
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(contracttest.Path(t, "fixtures/image/minimal.yml"))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		MinSeverity: DefaultMinSeverity,
		Mode:        DefaultMode,
		StatePath:   DefaultStatePath,
		Digest:      Digest{Time: DefaultDigestTime, Timezone: DefaultTimezone},
	}
	if cfg.MinSeverity != want.MinSeverity || cfg.Mode != want.Mode || cfg.StatePath != want.StatePath || cfg.Digest != want.Digest {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if cfg.Feed.PollInterval != DefaultPollInterval {
		t.Errorf("poll interval = %q", cfg.Feed.PollInterval)
	}
}

func TestParseRejects(t *testing.T) {
	const valid = `version: 1
feed:
  url: https://feed.example.org/api/v1/
products:
  - slug: postgresql
    version: "17"
channels:
  - type: discord
    url_env: DISCORD_WEBHOOK_URL
`
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]struct{ from, to, want string }{
		"unquoted number version": {`version: "17"`, `version: 17.10`, "quoted string"},
		"unknown key":             {"url_env: DISCORD_WEBHOOK_URL", "url: https://discord.example.invalid/x", "field url not found"},
		"lowercase env name":      {"DISCORD_WEBHOOK_URL", "discord_webhook", "url_env"},
		"feed not under api v1":   {"/api/v1/", "/feed/", "feed.url"},
		"bad slug":                {"slug: postgresql", "slug: PostgreSQL", "products[0].slug"},
		"wrong version":           {"version: 1\n", "version: 2\n", "version: must be 1"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(valid, tc.from, tc.to, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	if _, err := Parse(nil); err == nil {
		t.Error("empty file accepted")
	}
	if _, err := Parse([]byte(valid + "---\nversion: 1\n")); err == nil {
		t.Error("second document accepted")
	}
}

// TestFixturesAgreeWithSchema pins the Go rules to schemas/v1/image-config.schema.json:
// fixtures/image/*.yml pass both, invalid/ fails both, invalid-semantic/ passes the
// schema and fails only the rules a schema cannot express.
func TestFixturesAgreeWithSchema(t *testing.T) {
	schema := contracttest.Schema(t, "image-config")
	dir := contracttest.Path(t, "fixtures/image")
	groups := map[string]struct{ schemaOK, goOK bool }{
		"":                 {true, true},
		"invalid":          {false, false},
		"invalid-semantic": {true, false},
	}
	total := 0
	for sub, want := range groups {
		files, err := filepath.Glob(filepath.Join(dir, sub, "*.yml"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no fixtures in fixtures/image/%s", sub)
		}
		for _, file := range files {
			total++
			name := filepath.Join(sub, filepath.Base(file))
			schemaErr := schema.Validate(contracttest.LoadData(t, file))
			_, goErr := Load(file)
			if (schemaErr == nil) != want.schemaOK {
				t.Errorf("%s: schema accepted=%v, want %v (%v)", name, schemaErr == nil, want.schemaOK, schemaErr)
			}
			if (goErr == nil) != want.goOK {
				t.Errorf("%s: Go accepted=%v, want %v (%v)", name, goErr == nil, want.goOK, goErr)
			}
		}
	}
	if total < 9 {
		t.Errorf("only %d fixtures checked", total)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yml"))
	if !os.IsNotExist(err) {
		t.Fatalf("err = %v, want not exist", err)
	}
}
