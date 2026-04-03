// Package collector provides shared infrastructure for API clients.
package collector

import (
	"net/http"
	"time"
)

// NewHTTPClient returns an http.Client with a shared transport configured
// for connection pooling across all collectors. Each collector should use
// this instead of creating its own http.Client so that idle connections
// to the same hosts (e.g. registry.npmjs.org) are reused.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: sharedTransport,
	}
}

var sharedTransport http.RoundTripper = &http.Transport{
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 10,
	IdleConnTimeout:     90 * time.Second,
}
