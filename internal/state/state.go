// Package state handles persistence for the watch command's polling state.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State represents the persisted watch state.
type State struct {
	SchemaVersion int                     `json:"schema_version"`
	UpdatedAt     time.Time               `json:"updated_at"`
	Packages      map[string]PackageState `json:"packages"`
}

// PackageState tracks what has been scanned for a single package.
type PackageState struct {
	LastScannedVersion string    `json:"last_scanned_version"`
	LastTargetScore    float64   `json:"last_target_score"`
	LastRiskLevel      string    `json:"last_risk_level"`
	LastScanTime       time.Time `json:"last_scan_time"`
	ETag               string    `json:"etag"`
}

// New returns an empty state ready for use.
func New() *State {
	return &State{
		SchemaVersion: 1,
		Packages:      make(map[string]PackageState),
	}
}

// Update merges a scan result into the state for a given package.
func (s *State) Update(packageName, version string, score float64, risk, etag string) {
	s.Packages[packageName] = PackageState{
		LastScannedVersion: version,
		LastTargetScore:    score,
		LastRiskLevel:      risk,
		LastScanTime:       time.Now().UTC(),
		ETag:               etag,
	}
	s.UpdatedAt = time.Now().UTC()
}

// Load reads state from a JSON file. Returns an empty state if the file does not exist.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}

	if s.Packages == nil {
		s.Packages = make(map[string]PackageState)
	}
	return &s, nil
}

// Save writes state to a JSON file atomically using a temp file and rename.
func Save(path string, s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".chainrecon-state-*.json")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp state file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename state file: %w", err)
	}
	return nil
}
