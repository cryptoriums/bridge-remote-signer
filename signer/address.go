package signer

import (
	"context"
	"fmt"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

// Bech32Address derives the bech32 account address for the signer's secp256k1
// public key under the given prefix, using the standard Cosmos derivation
// (sha256 + ripemd160 of the compressed key). It is the single source of truth
// for the signer's identity: both the authenticated gRPC GetAddress and the
// plain HTTP /address endpoint serve exactly this value.
func Bech32Address(ctx context.Context, s Signer, prefix string) (string, error) {
	if prefix == "" {
		return "", fmt.Errorf("prefix must not be empty")
	}
	pubKeyBytes, err := s.GetPublicKey(ctx)
	if err != nil {
		return "", fmt.Errorf("get public key: %w", err)
	}
	if len(pubKeyBytes) != 33 {
		return "", fmt.Errorf("invalid public key length %d, expected 33", len(pubKeyBytes))
	}
	pubKey := &cosmossecp.PubKey{Key: pubKeyBytes}
	addr, err := bech32.ConvertAndEncode(prefix, pubKey.Address().Bytes())
	if err != nil {
		return "", fmt.Errorf("bech32 encode: %w", err)
	}
	return addr, nil
}
