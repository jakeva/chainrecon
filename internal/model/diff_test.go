package model

import (
	"encoding/json"
	"testing"
)

func TestCodeFinding_ToFinding_WithFileAndLine(t *testing.T) {
	cf := CodeFinding{
		Severity: SeverityCritical,
		Signal:   "lifecycle",
		Message:  "New postinstall script",
		Detail:   "curl | bash",
		File:     "package.json",
		Line:     12,
	}

	f := cf.ToFinding()
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", f.Severity)
	}
	if f.Signal != "lifecycle" {
		t.Errorf("Signal = %q, want lifecycle", f.Signal)
	}
	want := "[package.json:12] curl | bash"
	if f.Detail != want {
		t.Errorf("Detail = %q, want %q", f.Detail, want)
	}
}

func TestCodeFinding_ToFinding_FileOnly(t *testing.T) {
	cf := CodeFinding{
		Severity: SeverityHigh,
		Signal:   "obfuscation",
		Message:  "eval() detected",
		Detail:   "eval call in minified code",
		File:     "dist/index.js",
	}

	f := cf.ToFinding()
	want := "[dist/index.js] eval call in minified code"
	if f.Detail != want {
		t.Errorf("Detail = %q, want %q", f.Detail, want)
	}
}

func TestCodeFinding_ToFinding_NoFile(t *testing.T) {
	cf := CodeFinding{
		Severity: SeverityMedium,
		Signal:   "depinjection",
		Message:  "New dependency added",
		Detail:   "malicious-pkg@1.0.0",
	}

	f := cf.ToFinding()
	if f.Detail != "malicious-pkg@1.0.0" {
		t.Errorf("Detail = %q, want %q", f.Detail, "malicious-pkg@1.0.0")
	}
}

func TestCodeFindingsToFindings(t *testing.T) {
	cfs := []CodeFinding{
		{Severity: SeverityCritical, Signal: "a", Message: "msg1"},
		{Severity: SeverityLow, Signal: "b", Message: "msg2"},
	}

	fs := CodeFindingsToFindings(cfs)
	if len(fs) != 2 {
		t.Fatalf("len = %d, want 2", len(fs))
	}
	if fs[0].Signal != "a" || fs[1].Signal != "b" {
		t.Errorf("unexpected signals: %q, %q", fs[0].Signal, fs[1].Signal)
	}
}

func TestCodeFindingsToFindings_Nil(t *testing.T) {
	fs := CodeFindingsToFindings(nil)
	if fs != nil {
		t.Errorf("expected nil, got %v", fs)
	}
}

func TestReleaseDiff_FileCount(t *testing.T) {
	d := ReleaseDiff{
		Added:    make([]FileDiff, 3),
		Removed:  make([]FileDiff, 1),
		Modified: make([]FileDiff, 2),
	}
	a, r, m := d.FileCount()
	if a != 3 || r != 1 || m != 2 {
		t.Errorf("FileCount = (%d, %d, %d), want (3, 1, 2)", a, r, m)
	}
}

func TestReleaseDiff_JSONRoundTrip(t *testing.T) {
	d := ReleaseDiff{
		Package:    "express",
		OldVersion: "4.18.2",
		NewVersion: "4.19.0",
		Added: []FileDiff{
			{Path: "new.js", Status: DiffAdded},
		},
	}

	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got ReleaseDiff
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Package != "express" || got.OldVersion != "4.18.2" || got.NewVersion != "4.19.0" {
		t.Errorf("unexpected package/version: %q %q %q", got.Package, got.OldVersion, got.NewVersion)
	}
	if len(got.Added) != 1 || got.Added[0].Path != "new.js" {
		t.Errorf("unexpected added files: %v", got.Added)
	}
}
