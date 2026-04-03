package keymanager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// LocalManager is the 0.1.0 KeyManager implementation.
// It stores wrapped DEKs in a JSON file, with the KEK held in memory
// (loaded from an environment variable or key file at startup).
type LocalManager struct {
	kek       []byte          // Key encryption key (32 bytes, AES-256)
	deks      map[string]*DEK // bucketID -> DEK
	storePath string
	mu        sync.RWMutex
}

// LocalManagerConfig holds configuration for the local key manager.
type LocalManagerConfig struct {
	KEK       []byte // 32-byte key encryption key
	StorePath string // Path to the wrapped DEK store file
}

// NewLocalManager creates a key manager that stores wrapped DEKs locally.
func NewLocalManager(cfg LocalManagerConfig) (*LocalManager, error) {
	if len(cfg.KEK) != 32 {
		return nil, fmt.Errorf("KEK must be exactly 32 bytes (AES-256), got %d", len(cfg.KEK))
	}

	m := &LocalManager{
		kek:       cfg.KEK,
		deks:      make(map[string]*DEK),
		storePath: cfg.StorePath,
	}

	// Load existing wrapped DEKs
	if err := m.loadStore(); err != nil {
		return nil, fmt.Errorf("load key store: %w", err)
	}

	return m, nil
}

// GenerateDEK creates a new AES-256 data encryption key for a bucket.
func (m *LocalManager) GenerateDEK(ctx context.Context, bucketID string) (*DEK, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate random 32-byte key
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}

	// Wrap the DEK with the KEK using AES-GCM
	wrapped, err := m.wrapKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("wrap DEK: %w", err)
	}

	dek := &DEK{
		ID:         fmt.Sprintf("dek-%s-%d", bucketID, time.Now().UnixNano()),
		BucketID:   bucketID,
		Key:        rawKey,
		CreatedAt:  time.Now().Unix(),
		WrappedKey: wrapped,
	}

	m.deks[bucketID] = dek

	if err := m.saveStore(); err != nil {
		return nil, fmt.Errorf("persist key store: %w", err)
	}

	return dek, nil
}

// GetDEK retrieves and unwraps the DEK for a bucket.
func (m *LocalManager) GetDEK(ctx context.Context, bucketID string) (*DEK, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	dek, ok := m.deks[bucketID]
	if !ok {
		return nil, fmt.Errorf("no DEK for bucket %q (may have been shredded)", bucketID)
	}

	// Unwrap if needed (key might have been loaded from store without raw key)
	if dek.Key == nil {
		raw, err := m.unwrapKey(dek.WrappedKey)
		if err != nil {
			return nil, fmt.Errorf("unwrap DEK: %w", err)
		}
		dek.Key = raw
	}

	return dek, nil
}

// ShredDEK permanently destroys a DEK, making the encrypted data unrecoverable.
func (m *LocalManager) ShredDEK(ctx context.Context, bucketID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dek, ok := m.deks[bucketID]
	if !ok {
		return nil // Already gone — idempotent
	}

	// Zero out key material in memory
	for i := range dek.Key {
		dek.Key[i] = 0
	}
	for i := range dek.WrappedKey {
		dek.WrappedKey[i] = 0
	}

	delete(m.deks, bucketID)

	return m.saveStore()
}

// RotateKEK generates a new KEK and re-wraps all active DEKs.
func (m *LocalManager) RotateKEK(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate new KEK
	newKEK := make([]byte, 32)
	if _, err := rand.Read(newKEK); err != nil {
		return fmt.Errorf("generate new KEK: %w", err)
	}

	// Unwrap all DEKs with old KEK, re-wrap with new KEK
	oldKEK := m.kek
	for bucketID, dek := range m.deks {
		// Unwrap with old KEK
		if dek.Key == nil {
			raw, err := m.unwrapKey(dek.WrappedKey)
			if err != nil {
				return fmt.Errorf("unwrap DEK %s during rotation: %w", bucketID, err)
			}
			dek.Key = raw
		}

		// Re-wrap with new KEK
		m.kek = newKEK
		wrapped, err := m.wrapKey(dek.Key)
		if err != nil {
			m.kek = oldKEK // Rollback
			return fmt.Errorf("re-wrap DEK %s: %w", bucketID, err)
		}
		dek.WrappedKey = wrapped
	}

	m.kek = newKEK

	// Zero old KEK
	for i := range oldKEK {
		oldKEK[i] = 0
	}

	return m.saveStore()
}

// ListDEKs returns metadata for all active DEKs.
func (m *LocalManager) ListDEKs(ctx context.Context) ([]DEKMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metas := make([]DEKMetadata, 0, len(m.deks))
	for _, dek := range m.deks {
		metas = append(metas, DEKMetadata{
			ID:        dek.ID,
			BucketID:  dek.BucketID,
			CreatedAt: dek.CreatedAt,
			Active:    true,
		})
	}
	return metas, nil
}

// Close zeros out key material.
func (m *LocalManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, dek := range m.deks {
		for i := range dek.Key {
			dek.Key[i] = 0
		}
	}
	for i := range m.kek {
		m.kek[i] = 0
	}
	return nil
}

// wrapKey encrypts a DEK with the KEK using AES-256-GCM.
func (m *LocalManager) wrapKey(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.kek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// unwrapKey decrypts a wrapped DEK using the KEK.
func (m *LocalManager) unwrapKey(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.kek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// storedDEK is the on-disk representation (no raw key material).
type storedDEK struct {
	ID         string `json:"id"`
	BucketID   string `json:"bucket_id"`
	WrappedKey []byte `json:"wrapped_key"`
	CreatedAt  int64  `json:"created_at"`
}

func (m *LocalManager) saveStore() error {
	stored := make([]storedDEK, 0, len(m.deks))
	for _, dek := range m.deks {
		stored = append(stored, storedDEK{
			ID:         dek.ID,
			BucketID:   dek.BucketID,
			CreatedAt:  dek.CreatedAt,
			WrappedKey: dek.WrappedKey,
		})
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically via temp file + rename
	tmp := m.storePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.storePath)
}

func (m *LocalManager) loadStore() error {
	data, err := os.ReadFile(m.storePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var stored []storedDEK
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse key store: %w", err)
	}

	for _, s := range stored {
		m.deks[s.BucketID] = &DEK{
			ID:         s.ID,
			BucketID:   s.BucketID,
			CreatedAt:  s.CreatedAt,
			WrappedKey: s.WrappedKey,
		}
	}

	return nil
}
