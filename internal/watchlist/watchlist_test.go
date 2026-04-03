package watchlist

import (
	"os"
	"path/filepath"
	"testing"
)

func testdataPath(name string) string {
	return filepath.Join("..", "..", "testdata", "watchlist", name)
}

func TestLoad_Valid(t *testing.T) {
	wl, err := Load(testdataPath("valid.yml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(wl.Packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(wl.Packages))
	}

	if wl.Packages[0].Name != "express" {
		t.Errorf("packages[0].Name = %q, want %q", wl.Packages[0].Name, "express")
	}
	if wl.Packages[1].Name != "axios" {
		t.Errorf("packages[1].Name = %q, want %q", wl.Packages[1].Name, "axios")
	}
	if wl.Packages[2].Name != "@anthropic-ai/sdk" {
		t.Errorf("packages[2].Name = %q, want %q", wl.Packages[2].Name, "@anthropic-ai/sdk")
	}

	if wl.Defaults.Threshold != 50.0 {
		t.Errorf("defaults.threshold = %f, want 50.0", wl.Defaults.Threshold)
	}
	if wl.Packages[1].Threshold != 70.0 {
		t.Errorf("packages[1].threshold = %f, want 70.0", wl.Packages[1].Threshold)
	}
}

func TestLoad_NoPackages(t *testing.T) {
	_, err := Load(testdataPath("no-packages.yml"))
	if err == nil {
		t.Fatal("expected error for empty packages list")
	}
}

func TestLoad_Duplicate(t *testing.T) {
	_, err := Load(testdataPath("duplicate.yml"))
	if err == nil {
		t.Fatal("expected error for duplicate package")
	}
}

func TestLoad_NotFound(t *testing.T) {
	_, err := Load("/nonexistent/path.yml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yml")
	_ = os.WriteFile(path, []byte(":::not yaml"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestEffectiveThreshold_EntryOverride(t *testing.T) {
	wl := &Watchlist{
		Defaults: Defaults{Threshold: 50.0},
	}

	entry := Entry{Name: "axios", Threshold: 70.0}
	if got := wl.EffectiveThreshold(entry); got != 70.0 {
		t.Errorf("EffectiveThreshold = %f, want 70.0", got)
	}
}

func TestEffectiveThreshold_FallbackToDefault(t *testing.T) {
	wl := &Watchlist{
		Defaults: Defaults{Threshold: 50.0},
	}

	entry := Entry{Name: "express"}
	if got := wl.EffectiveThreshold(entry); got != 50.0 {
		t.Errorf("EffectiveThreshold = %f, want 50.0", got)
	}
}

func TestEffectiveThreshold_NoDefault(t *testing.T) {
	wl := &Watchlist{}
	entry := Entry{Name: "express"}
	if got := wl.EffectiveThreshold(entry); got != 0 {
		t.Errorf("EffectiveThreshold = %f, want 0", got)
	}
}
