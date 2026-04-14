package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
)

func init() {
	RegisterBackend("file", newFileSignerFromConfig)
}

// newFileSignerFromConfig is the BackendFactory for the file backend.
// It extracts the key_path from the raw config and creates a FileSigner.
func newFileSignerFromConfig(_ context.Context, raw map[string]any) (Signer, error) {
	keyPath, ok := raw["key_path"].(string)
	if !ok || keyPath == "" {
		return nil, errors.New("signer.key_path is required when backend is \"file\"")
	}
	return NewFileSigner(keyPath)
}

// FileSigner implements Signer using a secp256k1 private key loaded from disk.
// The key is loaded once at startup and held in memory — it is never re-read
// from disk during operation.
type FileSigner struct {
	privateKey       *ecdsa.PrivateKey
	compressedPubKey []byte     // 33-byte compressed secp256k1 public key, cached at startup
	mu               sync.Mutex // protects against concurrent Sign calls
}

// NewFileSigner loads a secp256k1 private key from keyPath and returns a FileSigner.
// keyPath must point to a file containing the hex-encoded 32-byte raw private key.
func NewFileSigner(keyPath string) (*FileSigner, error) {
	if keyPath == "" {
		return nil, errors.New("key_path is required for file signer backend")
	}

	privateKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key from %q: %w", keyPath, err)
	}

	compressedPubKey := crypto.CompressPubkey(&privateKey.PublicKey)

	return &FileSigner{
		privateKey:       privateKey,
		compressedPubKey: compressedPubKey,
	}, nil
}

// Sign implements Signer.
// Returns a 65-byte secp256k1 signature in Ethereum format: r || s || v, where v is 27 or 28.
func (s *FileSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, fmt.Errorf("Sign: msg must be exactly 32 bytes, got %d", len(msg))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// To produce signatures compatible with both the keyring signer and the contract,
	// we must SHA256-hash the input before signing.
	hash := sha256.Sum256(msg)

	sig, err := crypto.Sign(hash[:], s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("Sign: secp256k1 signing failed: %w", err)
	}

	// go-ethereum returns v as 0 or 1 , adjust to 27 or 28 for ecrecover.
	sig[64] += 27
	return sig, nil
}

// GetPublicKey implements Signer.
// Returns a copy of the cached compressed 33-byte secp256k1 public key.
func (s *FileSigner) GetPublicKey(_ context.Context) ([]byte, error) {
	out := make([]byte, len(s.compressedPubKey))
	copy(out, s.compressedPubKey)
	return out, nil
}

// loadPrivateKey reads a hex-encoded secp256k1 private key from disk.
func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	// Ensure the key file isn't readable by others.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot stat key file: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		return nil, fmt.Errorf(
			"key file %s has permissions %04o; must not be readable by group or others (expected 0600)",
			path, perm,
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read key file: %w", err)
	}

	// Strip whitespace and optional 0x prefix.
	hexStr := strings.ToLower(strings.TrimSpace(string(data)))
	hexStr = strings.TrimPrefix(hexStr, "0x")

	keyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("key file contains invalid hex: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(keyBytes))
	}

	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid secp256k1 private key: %w", err)
	}

	return privateKey, nil
}
