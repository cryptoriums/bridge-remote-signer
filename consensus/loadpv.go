package consensus

import (
	"fmt"
	"os"

	cmtbytes "github.com/cometbft/cometbft/libs/bytes"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/privval"
)

type privValidatorKeyFile struct {
	PrivKey crypto.PrivKey `json:"priv_key"`
}

// LoadCometFilePV loads consensus key and last-sign state like CometBFT's
// LoadFilePV but returns an error instead of exiting the process.
func LoadCometFilePV(keyFilePath, stateFilePath string) (*privval.FilePV, error) {
	keyJSON, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	var kf privValidatorKeyFile
	if err := cmtjson.Unmarshal(keyJSON, &kf); err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}
	if kf.PrivKey == nil {
		return nil, fmt.Errorf("missing priv_key in %s", keyFilePath)
	}

	pv := privval.NewFilePV(kf.PrivKey, keyFilePath, stateFilePath)

	stateJSON, err := os.ReadFile(stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return pv, nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}
	var st struct {
		Height    int64             `json:"height"`
		Round     int32             `json:"round"`
		Step      int8              `json:"step"`
		Signature []byte            `json:"signature,omitempty"`
		SignBytes cmtbytes.HexBytes `json:"signbytes,omitempty"`
	}
	if err := cmtjson.Unmarshal(stateJSON, &st); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}
	ls := &pv.LastSignState
	ls.Height = st.Height
	ls.Round = st.Round
	ls.Step = st.Step
	ls.Signature = st.Signature
	ls.SignBytes = st.SignBytes
	return pv, nil
}
