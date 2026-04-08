package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"runtime"
	"testing"
)

func TestExpectedAssetName(t *testing.T) {
	name := expectedAssetName("0.3.0")
	if name == "" {
		t.Fatal("expected non-empty asset name")
	}

	wantOS := runtime.GOOS
	wantArch := runtime.GOARCH

	if wantOS == "windows" {
		if got := name; got != "chainrecon_0.3.0_windows_"+wantArch+".zip" {
			t.Errorf("got %q", got)
		}
	} else {
		if got := name; got != "chainrecon_0.3.0_"+wantOS+"_"+wantArch+".tar.gz" {
			t.Errorf("got %q", got)
		}
	}
}

func TestIsHomebrewPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/opt/homebrew/Cellar/chainrecon/0.3.0/bin/chainrecon", true},
		{"/usr/local/Cellar/chainrecon/0.3.0/bin/chainrecon", true},
		{"/home/linuxbrew/.linuxbrew/Cellar/chainrecon/0.3.0/bin/chainrecon", true},
		{"/usr/local/bin/chainrecon", false},
		{"/home/user/go/bin/chainrecon", false},
	}
	for _, tt := range tests {
		if got := isHomebrewPath(tt.path); got != tt.want {
			t.Errorf("isHomebrewPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestExtractFromTarGz(t *testing.T) {
	content := []byte("#!/bin/sh\necho hello\n")
	data := buildTarGz(t, "chainrecon", content)

	got, err := extractFromTarGz(data)
	if err != nil {
		t.Fatalf("extractFromTarGz: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestExtractFromTarGz_NotFound(t *testing.T) {
	data := buildTarGz(t, "other-binary", []byte("nope"))

	_, err := extractFromTarGz(data)
	if err == nil {
		t.Fatal("expected error when binary not in archive")
	}
}

func buildTarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
