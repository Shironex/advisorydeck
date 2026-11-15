// Command advisorydeck is the Advisorydeck notifier image.
//
// This build only checks a config file; polling and notifications arrive in later releases.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Shironex/advisorydeck/image/internal/config"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Usage:
  advisorydeck check-config [-config path]   validate a config file (default %s)
  advisorydeck version                       print the version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, config.DefaultPath)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "check-config":
		fs := flag.NewFlagSet("check-config", flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("config", config.DefaultPath, "config file to check")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		cfg, err := config.Load(*path)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", *path, err)
			return 1
		}
		fmt.Fprintf(stdout, "%s: ok (%d products, %d channels, mode %s, min severity %s)\n",
			*path, len(cfg.Products), len(cfg.Channels), cfg.Mode, cfg.MinSeverity)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		fmt.Fprintf(stderr, usage, config.DefaultPath)
		return 2
	}
}
