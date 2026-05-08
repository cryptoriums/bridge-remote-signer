package consensus

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
)

// nodeKeyJSON matches CometBFT node_key.json (long-term P2P / privval conn identity).
type nodeKeyJSON struct {
	PrivKey cryptoKeyJSON `json:"priv_key"`
}

type cryptoKeyJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// privValidatorKeyJSON matches priv_validator_key.json (consensus key file).
type privValidatorKeyJSON struct {
	PrivKey cryptoKeyJSON `json:"priv_key"`
}

// LoadEd25519PrivKey loads an Ed25519 private key used for the SecretConnection
// handshake when dialing priv_validator_laddr. Supports:
//   - CometBFT node_key.json or priv_validator_key.json (JSON)
//   - Raw file containing 64-byte base64-encoded expanded Ed25519 key (TMKMS-style)
func LoadEd25519PrivKey(path string) (crypto.PrivKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = []byte(strings.TrimSpace(string(b)))

	if len(b) > 0 && b[0] == '{' {
		var nk nodeKeyJSON
		if err := cmtjson.Unmarshal(b, &nk); err == nil && nk.PrivKey.Type != "" {
			return decodeKeyJSON(nk.PrivKey)
		}
		var pvk privValidatorKeyJSON
		if err := cmtjson.Unmarshal(b, &pvk); err == nil && pvk.PrivKey.Type != "" {
			return decodeKeyJSON(pvk.PrivKey)
		}
		return nil, fmt.Errorf("unrecognized JSON key format in %s", path)
	}

	// Raw base64 (64 bytes)
	raw, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("expected JSON key file or base64 %d-byte ed25519 key in %s", ed25519.PrivateKeySize, path)
	}
	return ed25519.PrivKey(raw), nil
}

func decodeKeyJSON(k cryptoKeyJSON) (crypto.PrivKey, error) {
	switch k.Type {
	case "tendermint/PrivKeyEd25519", "comet/PrivKeyEd25519":
		raw, err := base64.StdEncoding.DecodeString(k.Value)
		if err != nil {
			return nil, err
		}
		return ed25519.PrivKey(raw), nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Type)
	}
}

// GenOrLoadConnKey writes a fresh connection identity to path if missing.
func GenOrLoadConnKey(path string) (crypto.PrivKey, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		pk := ed25519.GenPrivKey()
		nk := nodeKeyJSON{
			PrivKey: cryptoKeyJSON{
				Type:  "tendermint/PrivKeyEd25519",
				Value: base64.StdEncoding.EncodeToString(pk.Bytes()),
			},
		}
		out, err := json.MarshalIndent(nk, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, out, 0600); err != nil {
			return nil, err
		}
		return pk, nil
	}
	return LoadEd25519PrivKey(path)
}
