package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Shironex/advisorydeck/image/internal/contracttest"
)

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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != tc.code {
				t.Fatalf("exit %d, want %d (stderr %q)", code, tc.code, stderr.String())
			}
			if got := stdout.String() + stderr.String(); !strings.Contains(got, tc.out) {
				t.Fatalf("output %q does not contain %q", got, tc.out)
			}
		})
	}
}
