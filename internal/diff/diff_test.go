package diff

import (
	"strings"
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

func makeContents(name, version string, files map[string]string) *model.PackageContents {
	pc := &model.PackageContents{Name: name, Version: version}
	for path, content := range files {
		pc.Files = append(pc.Files, model.TarballFile{
			Path:    path,
			Content: []byte(content),
			Size:    int64(len(content)),
		})
	}
	return pc
}

func TestCompare_Identical(t *testing.T) {
	files := map[string]string{"index.js": "module.exports = {};"}
	old := makeContents("pkg", "1.0.0", files)
	new := makeContents("pkg", "1.0.1", files)

	d := Compare(old, new)
	a, r, m := d.FileCount()
	if a != 0 || r != 0 || m != 0 {
		t.Errorf("identical contents should have no changes, got +%d -%d ~%d", a, r, m)
	}
}

func TestCompare_AddedFile(t *testing.T) {
	old := makeContents("pkg", "1.0.0", map[string]string{
		"index.js": "old",
	})
	new := makeContents("pkg", "1.0.1", map[string]string{
		"index.js": "old",
		"new.js":   "new file",
	})

	d := Compare(old, new)
	if len(d.Added) != 1 {
		t.Fatalf("expected 1 added file, got %d", len(d.Added))
	}
	if d.Added[0].Path != "new.js" {
		t.Errorf("added file = %q, want new.js", d.Added[0].Path)
	}
	if d.Added[0].Status != model.DiffAdded {
		t.Errorf("status = %q, want added", d.Added[0].Status)
	}
}

func TestCompare_RemovedFile(t *testing.T) {
	old := makeContents("pkg", "1.0.0", map[string]string{
		"index.js": "keep",
		"old.js":   "removed",
	})
	new := makeContents("pkg", "1.0.1", map[string]string{
		"index.js": "keep",
	})

	d := Compare(old, new)
	if len(d.Removed) != 1 {
		t.Fatalf("expected 1 removed file, got %d", len(d.Removed))
	}
	if d.Removed[0].Path != "old.js" {
		t.Errorf("removed file = %q, want old.js", d.Removed[0].Path)
	}
}

func TestCompare_ModifiedFile(t *testing.T) {
	old := makeContents("pkg", "1.0.0", map[string]string{
		"index.js": "line1\nline2\nline3\n",
	})
	new := makeContents("pkg", "1.0.1", map[string]string{
		"index.js": "line1\nmodified\nline3\n",
	})

	d := Compare(old, new)
	if len(d.Modified) != 1 {
		t.Fatalf("expected 1 modified file, got %d", len(d.Modified))
	}
	if d.Modified[0].Path != "index.js" {
		t.Errorf("modified file = %q, want index.js", d.Modified[0].Path)
	}
	if d.Modified[0].UnifiedDiff == "" {
		t.Error("expected unified diff for text file")
	}
	if !strings.Contains(d.Modified[0].UnifiedDiff, "-line2") {
		t.Errorf("diff should contain -line2, got:\n%s", d.Modified[0].UnifiedDiff)
	}
	if !strings.Contains(d.Modified[0].UnifiedDiff, "+modified") {
		t.Errorf("diff should contain +modified, got:\n%s", d.Modified[0].UnifiedDiff)
	}
}

func TestCompare_BinaryFile(t *testing.T) {
	old := makeContents("pkg", "1.0.0", map[string]string{
		"data.bin": "old",
	})
	// New version has null bytes.
	new := &model.PackageContents{
		Name: "pkg", Version: "1.0.1",
		Files: []model.TarballFile{
			{Path: "data.bin", Content: []byte("new\x00data"), Size: 8},
		},
	}

	d := Compare(old, new)
	if len(d.Modified) != 1 {
		t.Fatalf("expected 1 modified file, got %d", len(d.Modified))
	}
	if !d.Modified[0].IsBinary {
		t.Error("file with null bytes should be flagged as binary")
	}
	if d.Modified[0].UnifiedDiff != "" {
		t.Error("binary files should not have a unified diff")
	}
}

func TestCompare_SortedOutput(t *testing.T) {
	old := makeContents("pkg", "1.0.0", map[string]string{})
	new := makeContents("pkg", "1.0.1", map[string]string{
		"z.js": "z",
		"a.js": "a",
		"m.js": "m",
	})

	d := Compare(old, new)
	if len(d.Added) != 3 {
		t.Fatalf("expected 3 added, got %d", len(d.Added))
	}
	if d.Added[0].Path != "a.js" || d.Added[1].Path != "m.js" || d.Added[2].Path != "z.js" {
		t.Errorf("added files not sorted: %v", []string{d.Added[0].Path, d.Added[1].Path, d.Added[2].Path})
	}
}

func TestCompare_PackageJSON(t *testing.T) {
	old := makeContents("pkg", "1.0.0", map[string]string{})
	old.PackageJSON = map[string]any{"name": "pkg", "version": "1.0.0"}

	new := makeContents("pkg", "1.0.1", map[string]string{})
	new.PackageJSON = map[string]any{"name": "pkg", "version": "1.0.1"}

	d := Compare(old, new)
	if d.OldPackageJSON == nil || d.NewPackageJSON == nil {
		t.Error("expected package.json to be carried through")
	}
	if d.OldPackageJSON["version"] != "1.0.0" {
		t.Errorf("old version = %v", d.OldPackageJSON["version"])
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("hello world")) {
		t.Error("text should not be binary")
	}
	if !isBinary([]byte("hello\x00world")) {
		t.Error("null byte should be binary")
	}
	if isBinary(nil) {
		t.Error("nil should not be binary")
	}
}

func TestUnifiedDiff_Simple(t *testing.T) {
	old := []byte("a\nb\nc\n")
	new := []byte("a\nx\nc\n")

	d := unifiedDiff("test.js", old, new)
	if !strings.Contains(d, "--- a/test.js") {
		t.Errorf("missing old header in:\n%s", d)
	}
	if !strings.Contains(d, "+++ b/test.js") {
		t.Errorf("missing new header in:\n%s", d)
	}
	if !strings.Contains(d, "-b") {
		t.Errorf("missing deletion in:\n%s", d)
	}
	if !strings.Contains(d, "+x") {
		t.Errorf("missing insertion in:\n%s", d)
	}
}
