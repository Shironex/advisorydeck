package contracttest

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestCatalogWorksInGo validates every catalog entry with Go's validator (format regex
// asserted with RE2) and checks each tag pattern compiles in Go with a version group.
func TestCatalogWorksInGo(t *testing.T) {
	schema := Schema(t, "product")
	files, err := filepath.Glob(Path(t, "catalog/*/*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 5 {
		t.Fatalf("found %d catalog files, want at least 5", len(files))
	}
	for _, file := range files {
		if err := schema.Validate(LoadData(t, file)); err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var entry struct {
			Images []struct {
				Ref        string `yaml:"ref"`
				TagPattern string `yaml:"tag_pattern"`
			} `yaml:"images"`
		}
		if err := yaml.Unmarshal(raw, &entry); err != nil {
			t.Fatal(err)
		}
		for _, img := range entry.Images {
			re, err := regexp.Compile(img.TagPattern)
			if err != nil {
				t.Errorf("%s %s: %v", file, img.Ref, err)
				continue
			}
			if re.SubexpIndex("version") < 0 {
				t.Errorf("%s %s: no version group", file, img.Ref)
			}
		}
	}
}
