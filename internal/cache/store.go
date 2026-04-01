// Package cache provides a local bbolt-backed caching layer for API responses.
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TTL constants for cached data per Section 7 of the project definition.
const (
	PackageMetadataTTL = 1 * time.Hour
	AttestationDataTTL = 24 * time.Hour
	DownloadCountTTL   = 6 * time.Hour
	GitHubWorkflowTTL  = 1 * time.Hour
)

// Store defines the interface for cache operations.
type Store interface {
	// Get retrieves a cached value by bucket and key. Returns nil if not found or expired.
	Get(ctx context.Context, bucket, key string) ([]byte, error)
	// Set stores a value with the given TTL.
	Set(ctx context.Context, bucket, key string, value []byte, ttl time.Duration) error
	// Clear removes all cached data.
	Clear(ctx context.Context) error
	// Close closes the underlying database.
	Close() error
}

// entry wraps cached data with an expiration timestamp.
type entry struct {
	Data      json.RawMessage `json:"data"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// BoltStore implements Store using bbolt.
type BoltStore struct {
	db  *bolt.DB
	now func() time.Time
}

// NewBoltStore creates a new bbolt-backed cache at the default path (~/.chainrecon/cache.db).
func NewBoltStore() (*BoltStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cache: get home dir: %w", err)
	}
	dir := filepath.Join(home, ".chainrecon")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cache: create dir: %w", err)
	}
	return NewBoltStoreAt(filepath.Join(dir, "cache.db"))
}

// NewBoltStoreAt creates a new bbolt-backed cache at the specified path.
func NewBoltStoreAt(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("cache: open bolt db: %w", err)
	}
	return &BoltStore{db: db, now: time.Now}, nil
}

// Get retrieves a cached value. Returns nil data if not found or expired.
func (s *BoltStore) Get(_ context.Context, bucket, key string) ([]byte, error) {
	var result []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(key))
		if raw == nil {
			return nil
		}
		var e entry
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil // treat corrupt entries as cache miss
		}
		if s.now().After(e.ExpiresAt) {
			return nil // expired
		}
		result = e.Data
		return nil
	})
	return result, err
}

// Set stores a value in the cache with the given TTL.
func (s *BoltStore) Set(_ context.Context, bucket, key string, value []byte, ttl time.Duration) error {
	e := entry{
		Data:      value,
		ExpiresAt: s.now().Add(ttl),
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("cache: marshal entry: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return fmt.Errorf("cache: create bucket %q: %w", bucket, err)
		}
		return b.Put([]byte(key), raw)
	})
}

// Clear removes all cached data by deleting all buckets.
func (s *BoltStore) Clear(_ context.Context) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			return tx.DeleteBucket(name)
		})
	})
}

// Close closes the underlying bbolt database.
func (s *BoltStore) Close() error {
	return s.db.Close()
}

// NopStore is a no-op cache that never caches (used when --no-cache is set).
type NopStore struct{}

// Get always returns nil (cache miss).
func (NopStore) Get(context.Context, string, string) ([]byte, error) { return nil, nil }

// Set is a no-op.
func (NopStore) Set(context.Context, string, string, []byte, time.Duration) error { return nil }

// Clear is a no-op.
func (NopStore) Clear(context.Context) error { return nil }

// Close is a no-op.
func (NopStore) Close() error { return nil }
