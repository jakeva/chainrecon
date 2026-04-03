// Package watchlist handles loading and validating package watch configurations.
package watchlist

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Entry represents a single package to watch.
type Entry struct {
	Name      string  `yaml:"name" json:"name"`
	Threshold float64 `yaml:"threshold,omitempty" json:"threshold,omitempty"`
}

// Defaults holds default values applied to all entries.
type Defaults struct {
	Threshold float64 `yaml:"threshold,omitempty" json:"threshold,omitempty"`
}

// Watchlist is the top-level watch configuration.
type Watchlist struct {
	Defaults Defaults `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Packages []Entry  `yaml:"packages" json:"packages"`
}

// Load reads and parses a watchlist from a YAML file.
func Load(path string) (*Watchlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read watchlist: %w", err)
	}

	var wl Watchlist
	if err := yaml.Unmarshal(data, &wl); err != nil {
		return nil, fmt.Errorf("parse watchlist: %w", err)
	}

	if err := wl.validate(); err != nil {
		return nil, err
	}

	return &wl, nil
}

// EffectiveThreshold returns the threshold for an entry, falling back to
// the watchlist default if the entry does not specify one.
func (wl *Watchlist) EffectiveThreshold(e Entry) float64 {
	if e.Threshold > 0 {
		return e.Threshold
	}
	return wl.Defaults.Threshold
}

func (wl *Watchlist) validate() error {
	if len(wl.Packages) == 0 {
		return fmt.Errorf("watchlist must contain at least one package")
	}

	seen := make(map[string]bool, len(wl.Packages))
	for i, p := range wl.Packages {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			return fmt.Errorf("watchlist entry %d: name is required", i)
		}
		if seen[name] {
			return fmt.Errorf("watchlist entry %d: duplicate package %q", i, name)
		}
		seen[name] = true
		wl.Packages[i].Name = name
	}
	return nil
}
