package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// NewUpdateCmd creates a cobra command that updates chainrecon to the latest release.
func NewUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update chainrecon to the latest release",
		Example: `  chainrecon update`,
		RunE:  runUpdate,
	}
}

type ghRelease struct {
	TagName string  `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func runUpdate(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	current := Version
	fmt.Fprintf(os.Stderr, "Current version: %s\n", current)

	// Check if installed via Homebrew.
	execPath, err := os.Executable()
	if err == nil {
		resolved, err := filepath.EvalSymlinks(execPath)
		if err == nil && isHomebrewPath(resolved) {
			return fmt.Errorf("chainrecon is managed by Homebrew, run: brew update && brew upgrade chainrecon")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	release, err := fetchLatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("check for updates: %w", err)
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	if latest == current {
		fmt.Fprintf(os.Stderr, "Already up to date.\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "New version available: %s\n", latest)

	assetName := expectedAssetName(latest)
	if assetName == "" {
		return fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	var downloadURL string
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return fmt.Errorf("release %s has no asset %q", release.TagName, assetName)
	}

	fmt.Fprintf(os.Stderr, "Downloading %s ...\n", assetName)
	binary, err := downloadAndExtract(ctx, downloadURL, assetName)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	if err := replaceBinary(binary); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Updated to %s.\n", latest)
	return nil
}

func isHomebrewPath(path string) bool {
	return strings.Contains(path, "/Cellar/") ||
		strings.Contains(path, "/homebrew/") ||
		strings.Contains(path, "/Homebrew/")
}

func fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/jakeva/chainrecon/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &release, nil
}

func expectedAssetName(version string) string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	if goos == "windows" && goarch == "arm64" {
		return ""
	}

	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}

	return fmt.Sprintf("chainrecon_%s_%s_%s.%s", version, goos, goarch, ext)
}

func downloadAndExtract(ctx context.Context, url, assetName string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read download: %w", err)
	}

	if strings.HasSuffix(assetName, ".zip") {
		return extractFromZip(data)
	}
	return extractFromTarGz(data)
}

func extractFromTarGz(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if filepath.Base(hdr.Name) == "chainrecon" && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("chainrecon binary not found in archive")
}

func extractFromZip(data []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	for _, f := range r.File {
		if filepath.Base(f.Name) == "chainrecon.exe" {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = rc.Close() }()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("chainrecon.exe not found in archive")
}

func replaceBinary(newBinary []byte) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}

	dir := filepath.Dir(execPath)
	tmp, err := os.CreateTemp(dir, ".chainrecon-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(newBinary); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod: %w", err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}
