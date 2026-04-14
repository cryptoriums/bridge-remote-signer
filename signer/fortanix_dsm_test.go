package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/fortanix/sdkms-client-go/sdkms"
)

// mockDSMClient simulates Fortanix DSM responses using a real local private key.
type mockDSMClient struct {
	ecdsaKey *ecdsa.PrivateKey
}

func (m *mockDSMClient) Sign(_ context.Context, body sdkms.SignRequest) (*sdkms.SignResponse, error) {
	msg := *body.Hash

	sig, err := crypto.Sign(msg, m.ecdsaKey)
	if err != nil {
		return nil, err
	}

	// DSM returns DER-encoded signatures for EC keys.
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])

	derSig, err := asn1.Marshal(ecdsaDERSig{R: r, S: s})
	if err != nil {
		return nil, err
	}

	return &sdkms.SignResponse{Signature: derSig}, nil
}

func (m *mockDSMClient) GetSobject(_ context.Context, _ *sdkms.GetSobjectParams, _ sdkms.SobjectDescriptor) (*sdkms.Sobject, error) {
	return nil, nil
}

func TestFortanixDSMSigner_SignMatchesTestVector(t *testing.T) {
	keyBytes, err := hex.DecodeString(testPrivKeyHex)
	requireNoError(t, err, "failed to decode private key")

	ecdsaKey, err := crypto.ToECDSA(keyBytes)
	requireNoError(t, err, "failed to create ECDSA key")

	compressedPubKey := crypto.CompressPubkey(&ecdsaKey.PublicKey)

	// Create a FortanixDSMSigner with the mock client.
	keyID := "test-key-id"
	signer := &FortanixDSMSigner{
		client:           &mockDSMClient{ecdsaKey: ecdsaKey},
		keyDescriptor:    sdkms.SobjectDescriptor{Kid: &keyID},
		compressedPubKey: compressedPubKey,
	}

	msg := []byte("TellorLayer: Initial bridge signature A for operator tellorvaloper1test")
	msgHash := sha256.Sum256(msg)

	sig, err := signer.Sign(context.Background(), msgHash[:])
	requireNoError(t, err, "FortanixDSMSigner.Sign failed")

	expectedSigBytes, err := hex.DecodeString(expectedSig)
	requireNoError(t, err, "failed to decode expected signature")

	requireEqual(t, sig[:64], expectedSigBytes, "signature should not match expected signature because of different v value")

	// Verify length.
	requireLen(t, sig, 65)

	// Verify v is 27 or 28.
	if sig[64] != 27 && sig[64] != 28 {
		t.Errorf("expected v=27 or v=28, got %d", sig[64])
	}

	// Recover and verify address using the double hash.
	recoverable := make([]byte, 65)
	copy(recoverable, sig)
	recoverable[64] -= 27

	doubleHash := sha256.Sum256(msgHash[:])
	pubkey, err := crypto.Ecrecover(doubleHash[:], recoverable)
	requireNoError(t, err, "Ecrecover failed")

	x := new(big.Int).SetBytes(pubkey[1:33])
	y := new(big.Int).SetBytes(pubkey[33:65])
	recoveredPubKey := ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
	recoveredAddr := crypto.PubkeyToAddress(recoveredPubKey)

	requireEqualString(t, recoveredAddr.Hex(), evmAddr, "recovery address mismatch")
}
