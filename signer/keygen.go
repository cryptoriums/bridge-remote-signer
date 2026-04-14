package signer

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateKeyToFile generates a new secp256k1 private key and writes it
// as a hex-encoded file at the given path.

// The file is written with mode 0600 (owner read/write only).
// The directory must already exist.
func GenerateKeyToFile(path string) error {
	if path == "" {
		return fmt.Errorf("key path must not be empty")
	}

	// Ensure the directory exists.
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("directory %q does not exist", dir)
	}

	// Refuse to overwrite an existing key.
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("key file %q already exists — refusing to overwrite", path)
	}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate secp256k1 key: %w", err)
	}

	keyHex := hex.EncodeToString(crypto.FromECDSA(privateKey))

	// Write with restricted permissions.
	if err := os.WriteFile(path, []byte(keyHex+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// PublicKeyFromFile loads a private key file and returns the compressed
// secp256k1 public key as a hex string, and the Ethereum-style address.
// Used by the `bridge-signer pubkey` CLI command to verify a key file.
func PublicKeyFromFile(path string) (pubKeyHex string, ethAddress string, err error) {
	privateKey, err := loadPrivateKey(path)
	if err != nil {
		return "", "", err
	}

	pubKey := privateKey.PublicKey
	compressed := crypto.CompressPubkey(&pubKey)
	ethAddr := crypto.PubkeyToAddress(pubKey)

	return hex.EncodeToString(compressed), ethAddr.Hex(), nil
}
