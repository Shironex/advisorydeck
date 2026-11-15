// Package config loads and validates the image's config file (advisorydeck.yml).
//
// The rules mirror schemas/v1/image-config.schema.json plus the checks a schema cannot
// express (unique products, minimum poll interval, real time zones). The fixtures in
// fixtures/image pin both sides: see config_test.go.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// Defaults for optional settings. Keep in sync with packages/contract/src/image-config.ts.
const (
	DefaultPath         = "/config/advisorydeck.yml"
	DefaultPollInterval = "30m"
	DefaultMinSeverity  = "high"
	DefaultMode         = "digest"
	DefaultDigestTime   = "08:00"
	DefaultTimezone     = "UTC"
	DefaultStatePath    = "/data/state.json"
)

// Config is the parsed config file.
type Config struct {
	Version     int       `yaml:"version"`
	Feed        Feed      `yaml:"feed"`
	Products    []Product `yaml:"products"`
	MinSeverity string    `yaml:"min_severity"`
	Mode        string    `yaml:"mode"`
	Digest      Digest    `yaml:"digest"`
	Channels    []Channel `yaml:"channels"`
	StatePath   string    `yaml:"state_path"`
}

// Feed says where the published feed lives and how often to poll it.
type Feed struct {
	URL          string `yaml:"url"`
	PollInterval string `yaml:"poll_interval"`
}

// Product is one thing the user runs: a catalog slug and a branch or exact version.
type Product struct {
	Slug    string `yaml:"slug"`
	Version Text   `yaml:"version"`
}

// Digest sets when the daily digest is sent.
type Digest struct {
	Time     Text   `yaml:"time"`
	Timezone string `yaml:"timezone"`
}

// Channel is a notification target. URLEnv names the environment variable holding the
// webhook URL; the URL itself never appears in the file.
type Channel struct {
	Type   string `yaml:"type"`
	URLEnv string `yaml:"url_env"`
	Name   string `yaml:"name"`
}

// Text is a string that must be written as a YAML string. An unquoted 17.10 would
// otherwise arrive as the number 17.1, so numbers are rejected with a hint to quote them.
type Text string

// UnmarshalYAML implements yaml.Unmarshaler.
func (t *Text) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("line %d: %q must be a quoted string, for example \"%s\"", node.Line, node.Value, node.Value)
	}
	*t = Text(node.Value)
	return nil
}

// Load reads, decodes, defaults and validates a config file. The path comes from the
// operator (a flag), so reading it is the point.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes, defaults and validates config bytes. Unknown keys are errors, so a
// webhook URL pasted under the wrong key is refused instead of ignored.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config file is empty")
		}
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config file must hold exactly one YAML document")
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Feed.PollInterval == "" {
		c.Feed.PollInterval = DefaultPollInterval
	}
	if c.MinSeverity == "" {
		c.MinSeverity = DefaultMinSeverity
	}
	if c.Mode == "" {
		c.Mode = DefaultMode
	}
	if c.Digest.Time == "" {
		c.Digest.Time = DefaultDigestTime
	}
	if c.Digest.Timezone == "" {
		c.Digest.Timezone = DefaultTimezone
	}
	if c.StatePath == "" {
		c.StatePath = DefaultStatePath
	}
}
