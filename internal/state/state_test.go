package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	s := New()
	if s.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", s.SchemaVersion)
	}
	if s.Packages == nil {
		t.Error("Packages map should not be nil")
	}
}

func TestUpdate(t *testing.T) {
	s := New()
	s.Update("express", "4.18.2", 55.0, "HIGH", `"abc"`)

	ps, ok := s.Packages["express"]
	if !ok {
		t.Fatal("expected express in state")
	}
	if ps.LastScannedVersion != "4.18.2" {
		t.Errorf("LastScannedVersion = %q, want %q", ps.LastScannedVersion, "4.18.2")
	}
	if ps.LastTargetScore != 55.0 {
		t.Errorf("LastTargetScore = %f, want 55.0", ps.LastTargetScore)
	}
	if ps.LastRiskLevel != "HIGH" {
		t.Errorf("LastRiskLevel = %q, want %q", ps.LastRiskLevel, "HIGH")
	}
	if ps.ETag != `"abc"` {
		t.Errorf("ETag = %q, want %q", ps.ETag, `"abc"`)
	}
	if s.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := New()
	s.Update("axios", "1.7.0", 42.0, "MEDIUM", `"etag1"`)

	if err := Save(path, s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", loaded.SchemaVersion)
	}

	ps, ok := loaded.Packages["axios"]
	if !ok {
		t.Fatal("expected axios in loaded state")
	}
	if ps.LastScannedVersion != "1.7.0" {
		t.Errorf("LastScannedVersion = %q, want %q", ps.LastScannedVersion, "1.7.0")
	}
	if ps.LastTargetScore != 42.0 {
		t.Errorf("LastTargetScore = %f, want 42.0", ps.LastTargetScore)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	s, err := Load("/nonexistent/state.json")
	if err != nil {
		t.Fatalf("Load should not error on missing file: %v", err)
	}
	if s.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", s.SchemaVersion)
	}
	if len(s.Packages) != 0 {
		t.Errorf("expected empty packages, got %d", len(s.Packages))
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	_ = os.WriteFile(path, []byte("not json"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSave_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Save initial state.
	s1 := New()
	s1.Update("pkg1", "1.0.0", 10.0, "LOW", "")
	if err := Save(path, s1); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Save updated state.
	s2 := New()
	s2.Update("pkg2", "2.0.0", 80.0, "CRITICAL", "")
	if err := Save(path, s2); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify the file contains only the second state.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var loaded State
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, ok := loaded.Packages["pkg1"]; ok {
		t.Error("expected pkg1 to be absent (overwritten)")
	}
	if _, ok := loaded.Packages["pkg2"]; !ok {
		t.Error("expected pkg2 in state")
	}
}
