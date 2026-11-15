// Package contracttest gives tests access to the repository's schemas and fixtures, so
// Go code is checked against the same contract files as the TypeScript side.
package contracttest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

// SchemaBase is the $id prefix of every v1 schema.
const SchemaBase = "https://raw.githubusercontent.com/Shironex/advisorydeck/main/schemas/v1/"

// RepoRoot walks up from the working directory to the folder holding schemas/v1.
func RepoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "schemas", "v1")); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("schemas/v1 not found above the working directory")
		}
		dir = parent
	}
}

// Path joins slash-separated parts onto the repository root.
func Path(t testing.TB, rel string) string {
	t.Helper()
	return filepath.Join(RepoRoot(t), filepath.FromSlash(rel))
}

// Schema compiles one v1 schema (for example "image-config") with formats asserted.
// Patterns and format regex use Go's RE2, which also proves they work outside JavaScript.
func Schema(t testing.TB, name string) *jsonschema.Schema {
	t.Helper()
	dir := Path(t, "schemas/v1")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".schema.json") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if err := c.AddResource(SchemaBase+e.Name(), doc); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Compile(SchemaBase + name + ".schema.json")
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return s
}

// LoadData reads a JSON or YAML file into the generic form the validator expects.
func LoadData(t testing.TB, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
		var v any
		if err := yaml.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if raw, err = json.Marshal(v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}
