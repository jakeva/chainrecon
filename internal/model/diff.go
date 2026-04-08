package model

import "fmt"

// DiffStatus indicates whether a file was added, removed, or modified between versions.
type DiffStatus string

const (
	DiffAdded    DiffStatus = "added"
	DiffRemoved  DiffStatus = "removed"
	DiffModified DiffStatus = "modified"
)

// TarballFile represents a single file extracted from an npm tarball.
type TarballFile struct {
	Path         string `json:"path"`
	Content      []byte `json:"-"`
	Size         int64  `json:"size"`
	IsExecutable bool   `json:"is_executable,omitempty"`
}

// PackageContents holds the extracted contents of an npm tarball.
type PackageContents struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Files       []TarballFile     `json:"files"`
	PackageJSON map[string]any    `json:"package_json,omitempty"`
}

// FileDiff describes the change to a single file between two versions.
type FileDiff struct {
	Path        string     `json:"path"`
	Status      DiffStatus `json:"status"`
	OldContent  []byte     `json:"-"`
	NewContent  []byte     `json:"-"`
	UnifiedDiff string     `json:"unified_diff,omitempty"`
	IsBinary    bool       `json:"is_binary,omitempty"`
}

// ReleaseDiff holds the complete diff between two versions of a package.
type ReleaseDiff struct {
	Package        string         `json:"package"`
	OldVersion     string         `json:"old_version"`
	NewVersion     string         `json:"new_version"`
	Added          []FileDiff     `json:"added,omitempty"`
	Removed        []FileDiff     `json:"removed,omitempty"`
	Modified       []FileDiff     `json:"modified,omitempty"`
	OldPackageJSON map[string]any `json:"old_package_json,omitempty"`
	NewPackageJSON map[string]any `json:"new_package_json,omitempty"`
}

// FileCount returns the total number of changed files.
func (d *ReleaseDiff) FileCount() (added, removed, modified int) {
	return len(d.Added), len(d.Removed), len(d.Modified)
}

// CodeFinding is a finding with file location context, produced by code analyzers.
type CodeFinding struct {
	Severity Severity `json:"severity"`
	Signal   string   `json:"signal"`
	Message  string   `json:"message"`
	Detail   string   `json:"detail"`
	File     string   `json:"file,omitempty"`
	Line     int      `json:"line,omitempty"`
}

// ToFinding converts a CodeFinding to a Finding, embedding file location in the detail.
func (cf CodeFinding) ToFinding() Finding {
	detail := cf.Detail
	if cf.File != "" {
		loc := cf.File
		if cf.Line > 0 {
			loc = fmt.Sprintf("%s:%d", cf.File, cf.Line)
		}
		if detail != "" {
			detail = fmt.Sprintf("[%s] %s", loc, detail)
		} else {
			detail = loc
		}
	}
	return Finding{
		Severity: cf.Severity,
		Signal:   cf.Signal,
		Message:  cf.Message,
		Detail:   detail,
	}
}

// CodeFindingsToFindings converts a slice of CodeFinding to a slice of Finding.
func CodeFindingsToFindings(cfs []CodeFinding) []Finding {
	if len(cfs) == 0 {
		return nil
	}
	findings := make([]Finding, len(cfs))
	for i, cf := range cfs {
		findings[i] = cf.ToFinding()
	}
	return findings
}
