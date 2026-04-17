package analyzer

import (
	"fmt"
	"strings"

	"github.com/jakeva/chainrecon/internal/model"
)

// NativeAddonAnalyzer detects the addition of native binaries, shared
// libraries, WebAssembly files, and binding.gyp build configs. Injecting a
// precompiled binary into a package is a way to hide malicious code that
// source audits would miss.
type NativeAddonAnalyzer interface {
	// Analyze checks added and modified files for native addon indicators.
	Analyze(diff *model.ReleaseDiff) []model.CodeFinding
}

// nativeAddonAnalyzer is the default implementation of NativeAddonAnalyzer.
type nativeAddonAnalyzer struct{}

// NewNativeAddonAnalyzer returns a new NativeAddonAnalyzer.
func NewNativeAddonAnalyzer() NativeAddonAnalyzer {
	return &nativeAddonAnalyzer{}
}

// binaryExtensions are file extensions for native addons and shared libraries.
var binaryExtensions = map[string]bool{
	".node":  true,
	".dylib": true,
	".so":    true,
	".dll":   true,
	".wasm":  true,
}

// Analyze looks at newly added files for native addon extensions and
// binding.gyp. It also checks modified files for changes to binding.gyp.
// A new .node file or new binding.gyp in a package that did not previously
// have one gets CRITICAL severity.
func (n *nativeAddonAnalyzer) Analyze(diff *model.ReleaseDiff) []model.CodeFinding {
	var findings []model.CodeFinding

	// Track whether the old version already had binding.gyp or .node files
	// by checking all file lists. If the old package.json has files we do not
	// enumerate here, we can at least check whether the old version had any
	// of these by looking at the modified and removed lists (which imply the
	// file existed before).
	hadBindingGyp := hasOldFile(diff, "binding.gyp")
	hadNodeFile := hasOldNodeFile(diff)

	for _, f := range diff.Added {
		base := fileBase(f.Path)

		if base == "binding.gyp" {
			sev := model.SeverityHigh
			if !hadBindingGyp {
				sev = model.SeverityCritical
			}
			findings = append(findings, model.CodeFinding{
				Severity: sev,
				Signal:   "native_addon",
				Message:  "binding.gyp added to package",
				Detail:   "Native addon build configuration introduced",
				File:     f.Path,
			})
			continue
		}

		ext := fileExt(f.Path)
		if binaryExtensions[ext] {
			sev := model.SeverityHigh
			if ext == ".node" && !hadNodeFile {
				sev = model.SeverityCritical
			}
			findings = append(findings, model.CodeFinding{
				Severity: sev,
				Signal:   "native_addon",
				Message:  fmt.Sprintf("Binary file %s added", base),
				Detail:   fmt.Sprintf("Native/binary file with extension %s", ext),
				File:     f.Path,
			})
		}
	}

	// Check modified files for binding.gyp changes.
	for _, f := range diff.Modified {
		if fileBase(f.Path) == "binding.gyp" {
			findings = append(findings, model.CodeFinding{
				Severity: model.SeverityHigh,
				Signal:   "native_addon",
				Message:  "binding.gyp was modified",
				Detail:   "Native addon build configuration changed",
				File:     f.Path,
			})
		}
	}

	return findings
}

// hasOldFile checks whether a file with the given base name existed in the
// previous version by looking at modified and removed file lists.
func hasOldFile(diff *model.ReleaseDiff, baseName string) bool {
	for _, f := range diff.Modified {
		if fileBase(f.Path) == baseName {
			return true
		}
	}
	for _, f := range diff.Removed {
		if fileBase(f.Path) == baseName {
			return true
		}
	}
	return false
}

// hasOldNodeFile checks whether the old version had any .node files.
func hasOldNodeFile(diff *model.ReleaseDiff) bool {
	for _, f := range diff.Modified {
		if fileExt(f.Path) == ".node" {
			return true
		}
	}
	for _, f := range diff.Removed {
		if fileExt(f.Path) == ".node" {
			return true
		}
	}
	return false
}

// fileBase returns the last path component.
func fileBase(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}

// fileExt returns the file extension including the dot.
func fileExt(path string) string {
	base := fileBase(path)
	idx := strings.LastIndex(base, ".")
	if idx < 0 {
		return ""
	}
	return base[idx:]
}
