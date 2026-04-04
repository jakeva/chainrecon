// Package diff compares two versions of an npm package.
package diff

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/chainrecon/chainrecon/internal/model"
)

// Compare produces a ReleaseDiff from two PackageContents.
func Compare(old, new *model.PackageContents) *model.ReleaseDiff {
	d := &model.ReleaseDiff{
		Package:    new.Name,
		OldVersion: old.Version,
		NewVersion: new.Version,
	}

	if old.PackageJSON != nil {
		d.OldPackageJSON = old.PackageJSON
	}
	if new.PackageJSON != nil {
		d.NewPackageJSON = new.PackageJSON
	}

	oldIndex := indexFiles(old.Files)
	newIndex := indexFiles(new.Files)

	// Added: in new but not old.
	for path, nf := range newIndex {
		if _, exists := oldIndex[path]; !exists {
			fd := model.FileDiff{
				Path:       path,
				Status:     model.DiffAdded,
				NewContent: nf.Content,
				IsBinary:   isBinary(nf.Content),
			}
			d.Added = append(d.Added, fd)
		}
	}

	// Removed: in old but not new.
	for path, of := range oldIndex {
		if _, exists := newIndex[path]; !exists {
			fd := model.FileDiff{
				Path:       path,
				Status:     model.DiffRemoved,
				OldContent: of.Content,
				IsBinary:   isBinary(of.Content),
			}
			d.Removed = append(d.Removed, fd)
		}
	}

	// Modified: in both with different content.
	for path, of := range oldIndex {
		nf, exists := newIndex[path]
		if !exists {
			continue
		}
		if hashContent(of.Content) == hashContent(nf.Content) {
			continue
		}
		binary := isBinary(of.Content) || isBinary(nf.Content)
		fd := model.FileDiff{
			Path:       path,
			Status:     model.DiffModified,
			OldContent: of.Content,
			NewContent: nf.Content,
			IsBinary:   binary,
		}
		if !binary && len(of.Content) > 0 && len(nf.Content) > 0 {
			fd.UnifiedDiff = unifiedDiff(path, of.Content, nf.Content)
		}
		d.Modified = append(d.Modified, fd)
	}

	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Path < d.Added[j].Path })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Path < d.Removed[j].Path })
	sort.Slice(d.Modified, func(i, j int) bool { return d.Modified[i].Path < d.Modified[j].Path })

	return d
}

func indexFiles(files []model.TarballFile) map[string]model.TarballFile {
	m := make(map[string]model.TarballFile, len(files))
	for _, f := range files {
		m[f.Path] = f
	}
	return m
}

func hashContent(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// isBinary checks for null bytes in the first 512 bytes.
func isBinary(data []byte) bool {
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	return bytes.Contains(check, []byte{0})
}

// unifiedDiff generates a simple unified diff between two byte slices.
func unifiedDiff(path string, old, new []byte) string {
	oldLines := splitLines(old)
	newLines := splitLines(new)

	// Simple LCS-based diff.
	edits := computeEdits(oldLines, newLines)
	if len(edits) == 0 {
		return ""
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("--- a/%s\n+++ b/%s\n", path, path))

	// Group edits into hunks.
	hunks := groupHunks(edits, len(oldLines), len(newLines), 3)
	for _, h := range hunks {
		buf.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", h.oldStart+1, h.oldCount, h.newStart+1, h.newCount))
		for _, line := range h.lines {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}

	return buf.String()
}

func splitLines(data []byte) []string {
	s := string(data)
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	// Remove trailing empty string from final newline.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

type editOp int

const (
	opEqual editOp = iota
	opInsert
	opDelete
)

type edit struct {
	op   editOp
	text string
}

// computeEdits uses an O(NM) LCS-based diff to produce a list of edits.
func computeEdits(a, b []string) []edit {
	n := len(a)
	m := len(b)

	if n == 0 && m == 0 {
		return nil
	}
	if n == 0 {
		edits := make([]edit, m)
		for i, line := range b {
			edits[i] = edit{op: opInsert, text: line}
		}
		return edits
	}
	if m == 0 {
		edits := make([]edit, n)
		for i, line := range a {
			edits[i] = edit{op: opDelete, text: line}
		}
		return edits
	}

	// Build LCS table.
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	// Backtrack to produce edits.
	var edits []edit
	i, j := n, m
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && a[i-1] == b[j-1] {
			edits = append(edits, edit{op: opEqual, text: a[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			edits = append(edits, edit{op: opInsert, text: b[j-1]})
			j--
		} else {
			edits = append(edits, edit{op: opDelete, text: a[i-1]})
			i--
		}
	}

	// Reverse.
	for l, r := 0, len(edits)-1; l < r; l, r = l+1, r-1 {
		edits[l], edits[r] = edits[r], edits[l]
	}

	return edits
}

type hunk struct {
	oldStart int
	oldCount int
	newStart int
	newCount int
	lines    []string
}

// groupHunks converts a flat edit list into unified diff hunks with context lines.
func groupHunks(edits []edit, oldLen, newLen, ctx int) []hunk {
	// Find the ranges of non-equal edits.
	type changeRange struct{ start, end int }
	var changes []changeRange

	for i, e := range edits {
		if e.op != opEqual {
			if len(changes) == 0 || i > changes[len(changes)-1].end+2*ctx {
				changes = append(changes, changeRange{i, i})
			} else {
				changes[len(changes)-1].end = i
			}
		}
	}

	var hunks []hunk
	for _, cr := range changes {
		start := cr.start - ctx
		if start < 0 {
			start = 0
		}
		end := cr.end + ctx + 1
		if end > len(edits) {
			end = len(edits)
		}

		var h hunk
		oldPos := 0
		newPos := 0
		// Count positions up to start.
		for i := 0; i < start; i++ {
			switch edits[i].op {
			case opEqual:
				oldPos++
				newPos++
			case opDelete:
				oldPos++
			case opInsert:
				newPos++
			}
		}
		h.oldStart = oldPos
		h.newStart = newPos

		for i := start; i < end; i++ {
			switch edits[i].op {
			case opEqual:
				h.lines = append(h.lines, " "+edits[i].text)
				h.oldCount++
				h.newCount++
			case opDelete:
				h.lines = append(h.lines, "-"+edits[i].text)
				h.oldCount++
			case opInsert:
				h.lines = append(h.lines, "+"+edits[i].text)
				h.newCount++
			}
		}

		hunks = append(hunks, h)
	}

	return hunks
}
