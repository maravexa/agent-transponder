// Package keymanager defines the interface for encryption key lifecycle management.
// The 0.1.0 implementation stores keys in a local encrypted keyfile.
// The 1.0.0 implementation will use Vault or cloud KMS (AWS/GCP/Azure).
package keymanager

import "context"

// DEK is a data encryption key used for a specific storage bucket.
type DEK struct {
	ID         string // Unique key identifier
	BucketID   string // The storage bucket this key encrypts
	Key        []byte // The raw key material (AES-256, 32 bytes)
	CreatedAt  int64  // Unix timestamp
	WrappedKey []byte // The key encrypted by the KEK (for storage)
}

// Manager handles data encryption key lifecycle.
// It generates, stores, retrieves, and destroys DEKs using envelope encryption:
// each DEK is wrapped (encrypted) by a key encryption key (KEK) so that
// destroying a DEK's record makes the data unrecoverable (crypto-shredding).
type Manager interface {
	// GenerateDEK creates a new data encryption key for a storage bucket.
	// The DEK is wrapped by the active KEK before being persisted.
	GenerateDEK(ctx context.Context, bucketID string) (*DEK, error)

	// GetDEK retrieves and unwraps the DEK for a storage bucket.
	// Returns an error if the key has been shredded.
	GetDEK(ctx context.Context, bucketID string) (*DEK, error)

	// ShredDEK permanently destroys the DEK for a storage bucket.
	// After this, data encrypted with this key is unrecoverable.
	// This is the core mechanism for secure deletion.
	ShredDEK(ctx context.Context, bucketID string) error

	// RotateKEK generates a new key encryption key and re-wraps all active DEKs.
	// The old KEK is destroyed after all DEKs are re-wrapped.
	RotateKEK(ctx context.Context) error

	// ListDEKs returns metadata (not key material) for all active DEKs.
	ListDEKs(ctx context.Context) ([]DEKMetadata, error)

	// Close releases resources.
	Close() error
}

// DEKMetadata is the non-sensitive portion of a DEK record.
type DEKMetadata struct {
	ID        string
	BucketID  string
	CreatedAt int64
	Active    bool
}
