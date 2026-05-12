package consensus

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
)

// ── LoadEd25519PrivKey ────────────────────────────────────────────────────────

func TestLoadEd25519PrivKey_NodeKeyJSON(t *testing.T) {
	key := ed25519.GenPrivKey()
	nk := nodeKeyJSON{
		PrivKey: cryptoKeyJSON{
			Type:  "tendermint/PrivKeyEd25519",
			Value: base64.StdEncoding.EncodeToString(key.Bytes()),
		},
	}
	data, err := json.MarshalIndent(nk, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node_key.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadEd25519PrivKey(path)
	if err != nil {
		t.Fatalf("LoadEd25519PrivKey(node_key.json) error: %v", err)
	}
	if !got.PubKey().Equals(key.PubKey()) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadEd25519PrivKey_PrivValidatorKeyJSON(t *testing.T) {
	key := ed25519.GenPrivKey()
	pvk := privValidatorKeyJSON{
		PrivKey: cryptoKeyJSON{
			Type:  "tendermint/PrivKeyEd25519",
			Value: base64.StdEncoding.EncodeToString(key.Bytes()),
		},
	}
	data, err := json.MarshalIndent(pvk, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "priv_validator_key.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadEd25519PrivKey(path)
	if err != nil {
		t.Fatalf("LoadEd25519PrivKey(priv_validator_key.json) error: %v", err)
	}
	if !got.PubKey().Equals(key.PubKey()) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadEd25519PrivKey_RawBase64(t *testing.T) {
	key := ed25519.GenPrivKey()
	encoded := base64.StdEncoding.EncodeToString(key.Bytes())
	path := filepath.Join(t.TempDir(), "connection.key")
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadEd25519PrivKey(path)
	if err != nil {
		t.Fatalf("LoadEd25519PrivKey(raw base64) error: %v", err)
	}
	if !got.PubKey().Equals(key.PubKey()) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadEd25519PrivKey_MissingFile(t *testing.T) {
	_, err := LoadEd25519PrivKey(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadEd25519PrivKey_UnrecognizedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"something":"else"}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadEd25519PrivKey(path)
	if err == nil {
		t.Fatal("expected error for unrecognized JSON format")
	}
}

func TestLoadEd25519PrivKey_UnsupportedKeyType(t *testing.T) {
	nk := nodeKeyJSON{
		PrivKey: cryptoKeyJSON{
			Type:  "tendermint/PrivKeySecp256k1",
			Value: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	data, _ := json.Marshal(nk)
	path := filepath.Join(t.TempDir(), "secp.json")
	_ = os.WriteFile(path, data, 0600)

	_, err := LoadEd25519PrivKey(path)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestLoadEd25519PrivKey_ShortRawBase64(t *testing.T) {
	// 32 bytes — too short for Ed25519 (needs 64)
	short := base64.StdEncoding.EncodeToString(make([]byte, 32))
	path := filepath.Join(t.TempDir(), "short.key")
	_ = os.WriteFile(path, []byte(short), 0600)

	_, err := LoadEd25519PrivKey(path)
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

// ── GenOrLoadConnKey ──────────────────────────────────────────────────────────

func TestGenOrLoadConnKey_CreatesOnMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection.key")
	key, err := GenOrLoadConnKey(path)
	if err != nil {
		t.Fatalf("GenOrLoadConnKey error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected key file to be created: %v", err)
	}
}

func TestGenOrLoadConnKey_LoadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection.key")

	// Create once
	key1, err := GenOrLoadConnKey(path)
	if err != nil {
		t.Fatal(err)
	}

	// Load again — must return the same key
	key2, err := GenOrLoadConnKey(path)
	if err != nil {
		t.Fatalf("second GenOrLoadConnKey error: %v", err)
	}
	if !key1.PubKey().Equals(key2.PubKey()) {
		t.Error("reloaded key does not match original")
	}
}

func TestGenOrLoadConnKey_FilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection.key")
	if _, err := GenOrLoadConnKey(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("key file has group/other permissions: %o", info.Mode().Perm())
	}
}
