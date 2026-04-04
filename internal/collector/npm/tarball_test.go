package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func buildTestTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		hdr := &tar.Header{
			Name:     "package/" + name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetchContents_Basic(t *testing.T) {
	pj := `{"name": "test-pkg", "version": "1.0.0", "scripts": {"postinstall": "echo hi"}}`
	tarball := buildTestTarball(t, map[string]string{
		"package.json": pj,
		"index.js":     "module.exports = {};",
		"lib/util.js":  "exports.foo = 1;",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	defer srv.Close()

	client := NewTarballClient()
	contents, err := client.FetchContents(context.Background(), "test-pkg", "1.0.0", srv.URL+"/test-pkg/-/test-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("FetchContents: %v", err)
	}

	if contents.Name != "test-pkg" {
		t.Errorf("Name = %q, want %q", contents.Name, "test-pkg")
	}
	if contents.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", contents.Version, "1.0.0")
	}
	if len(contents.Files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(contents.Files))
	}

	// Check package.json was parsed.
	if contents.PackageJSON == nil {
		t.Fatal("PackageJSON should be parsed")
	}
	if contents.PackageJSON["name"] != "test-pkg" {
		t.Errorf("PackageJSON name = %v", contents.PackageJSON["name"])
	}

	// Check file paths were stripped of "package/" prefix.
	paths := make(map[string]bool)
	for _, f := range contents.Files {
		paths[f.Path] = true
	}
	for _, want := range []string{"package.json", "index.js", "lib/util.js"} {
		if !paths[want] {
			t.Errorf("missing file %q in extracted contents", want)
		}
	}
}

func TestFetchContents_LargeFileSkipped(t *testing.T) {
	// Create a file just over MaxFileSize.
	bigContent := make([]byte, MaxFileSize+1)
	for i := range bigContent {
		bigContent[i] = 'x'
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name:     "package/big.dat",
		Mode:     0o644,
		Size:     int64(len(bigContent)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(bigContent); err != nil {
		t.Fatal(err)
	}

	smallContent := []byte("small")
	hdr2 := &tar.Header{
		Name:     "package/small.js",
		Mode:     0o644,
		Size:     int64(len(smallContent)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr2); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(smallContent); err != nil {
		t.Fatal(err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	client := NewTarballClient()
	contents, err := client.FetchContents(context.Background(), "big-pkg", "1.0.0", srv.URL)
	if err != nil {
		t.Fatalf("FetchContents: %v", err)
	}

	if len(contents.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(contents.Files))
	}

	// The big file should be tracked but have nil content.
	for _, f := range contents.Files {
		if f.Path == "big.dat" {
			if len(f.Content) != 0 {
				t.Error("big file should have no content (skipped)")
			}
			if f.Size != int64(len(bigContent)) {
				t.Errorf("big file size = %d, want %d", f.Size, len(bigContent))
			}
		}
	}
}

func TestFetchContents_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := NewTarballClient()
	_, err := client.FetchContents(context.Background(), "missing", "1.0.0", srv.URL)
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestStripPackagePrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"package/index.js", "index.js"},
		{"package/lib/util.js", "lib/util.js"},
		{"package/", ""},
		{"other/index.js", "other/index.js"},
		{"index.js", "index.js"},
	}
	for _, tt := range tests {
		if got := stripPackagePrefix(tt.input); got != tt.want {
			t.Errorf("stripPackagePrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
