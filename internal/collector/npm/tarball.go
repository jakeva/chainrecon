package npm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chainrecon/chainrecon/internal/collector"
	"github.com/chainrecon/chainrecon/internal/model"
)

const (
	// MaxTarballSize is the maximum total extracted size (50 MB).
	MaxTarballSize = 50 << 20
	// MaxFileSize is the maximum size for a single file (5 MB).
	MaxFileSize = 5 << 20
)

// TarballClient downloads and extracts npm package tarballs.
type TarballClient interface {
	// FetchContents downloads a tarball and extracts its files.
	FetchContents(ctx context.Context, packageName, version, tarballURL string) (*model.PackageContents, error)
}

type tarballClient struct {
	httpClient *http.Client
}

// NewTarballClient creates a new TarballClient.
func NewTarballClient() TarballClient {
	return &tarballClient{
		httpClient: collector.NewHTTPClient(60 * time.Second),
	}
}

// FetchContents downloads the tarball at the given URL and extracts its contents.
// Files exceeding MaxFileSize are skipped. Extraction stops if total size exceeds MaxTarballSize.
func (c *tarballClient) FetchContents(ctx context.Context, packageName, version, tarballURL string) (*model.PackageContents, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, fmt.Errorf("tarball: create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tarball: download %s@%s: %w", packageName, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tarball: %s@%s returned %d", packageName, version, resp.StatusCode)
	}

	// Limit total download to MaxTarballSize of compressed data.
	lr := io.LimitReader(resp.Body, MaxTarballSize)

	gz, err := gzip.NewReader(lr)
	if err != nil {
		return nil, fmt.Errorf("tarball: gzip %s@%s: %w", packageName, version, err)
	}
	defer func() { _ = gz.Close() }()

	contents := &model.PackageContents{
		Name:    packageName,
		Version: version,
	}

	tr := tar.NewReader(gz)
	var totalSize int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tarball: read %s@%s: %w", packageName, version, err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// npm tarballs prefix all files with "package/".
		path := stripPackagePrefix(hdr.Name)
		if path == "" {
			continue
		}

		if hdr.Size > MaxFileSize {
			contents.Files = append(contents.Files, model.TarballFile{
				Path: path,
				Size: hdr.Size,
			})
			// Discard the content but still track the file.
			_, _ = io.Copy(io.Discard, tr)
			continue
		}

		totalSize += hdr.Size
		if totalSize > MaxTarballSize {
			_, _ = fmt.Fprintf(os.Stderr, "tarball: %s@%s exceeds %d byte limit, truncating\n",
				packageName, version, MaxTarballSize)
			break
		}

		data, err := io.ReadAll(io.LimitReader(tr, MaxFileSize+1))
		if err != nil {
			return nil, fmt.Errorf("tarball: read file %s in %s@%s: %w", path, packageName, version, err)
		}

		isExec := hdr.Mode&0o111 != 0

		contents.Files = append(contents.Files, model.TarballFile{
			Path:         path,
			Content:      data,
			Size:         int64(len(data)),
			IsExecutable: isExec,
		})

		if path == "package.json" {
			var pj map[string]any
			if err := json.Unmarshal(data, &pj); err == nil {
				contents.PackageJSON = pj
			}
		}
	}

	return contents, nil
}

// stripPackagePrefix removes the "package/" prefix that npm tarballs use.
// Returns empty string if the path is the directory entry itself.
func stripPackagePrefix(name string) string {
	const prefix = "package/"
	if !strings.HasPrefix(name, prefix) {
		return name
	}
	stripped := strings.TrimPrefix(name, prefix)
	if stripped == "" || stripped == "." {
		return ""
	}
	return stripped
}
