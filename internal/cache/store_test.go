package cache

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *BoltStore {
	t.Helper()
	dir := t.TempDir()
	store, err := NewBoltStoreAt(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("NewBoltStoreAt: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestBoltStore_SetAndGet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	bucket := "metadata"
	key := "lodash"
	value := []byte(`{"name":"lodash"}`)

	if err := store.Set(ctx, bucket, key, value, 1*time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := store.Get(ctx, bucket, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Get returned %q, want %q", got, value)
	}
}

func TestBoltStore_GetNonExistentKey(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	got, err := store.Get(ctx, "no-such-bucket", "no-such-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("Get returned %q for non-existent key, want nil", got)
	}
}

func TestBoltStore_GetExpiredKey(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	bucket := "metadata"
	key := "express"
	value := []byte(`{"name":"express"}`)

	// Set with a 1-nanosecond TTL so the entry expires virtually immediately.
	if err := store.Set(ctx, bucket, key, value, 1*time.Nanosecond); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Small sleep to guarantee the TTL has elapsed.
	time.Sleep(5 * time.Millisecond)

	got, err := store.Get(ctx, bucket, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("Get returned %q for expired key, want nil", got)
	}
}

func TestBoltStore_Clear(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Populate two different buckets.
	if err := store.Set(ctx, "b1", "k1", []byte(`"v1"`), 1*time.Hour); err != nil {
		t.Fatalf("Set b1/k1: %v", err)
	}
	if err := store.Set(ctx, "b2", "k2", []byte(`"v2"`), 1*time.Hour); err != nil {
		t.Fatalf("Set b2/k2: %v", err)
	}

	if err := store.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	// Both keys should be gone after clearing.
	for _, tc := range []struct{ bucket, key string }{
		{"b1", "k1"},
		{"b2", "k2"},
	} {
		got, err := store.Get(ctx, tc.bucket, tc.key)
		if err != nil {
			t.Fatalf("Get %s/%s after Clear: %v", tc.bucket, tc.key, err)
		}
		if got != nil {
			t.Errorf("Get %s/%s after Clear returned %q, want nil", tc.bucket, tc.key, got)
		}
	}
}

func TestNopStore_GetReturnsNil(t *testing.T) {
	var s NopStore
	ctx := context.Background()

	got, err := s.Get(ctx, "bucket", "key")
	if err != nil {
		t.Fatalf("NopStore.Get: %v", err)
	}
	if got != nil {
		t.Errorf("NopStore.Get returned %q, want nil", got)
	}
}

func TestNopStore_SetClearCloseAreNoOps(t *testing.T) {
	var s NopStore
	ctx := context.Background()

	if err := s.Set(ctx, "b", "k", []byte(`"v"`), time.Hour); err != nil {
		t.Errorf("NopStore.Set: %v", err)
	}
	if err := s.Clear(ctx); err != nil {
		t.Errorf("NopStore.Clear: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("NopStore.Close: %v", err)
	}
}
