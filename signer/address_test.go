package signer

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

type addrStub struct {
	Signer
	pub []byte
	err error
}

func (a addrStub) GetPublicKey(context.Context) ([]byte, error) { return a.pub, a.err }

func TestBech32Address(t *testing.T) {
	// Compressed secp256k1 public key for private key 1 — a fixed, valid test vector.
	pub, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	addr, err := Bech32Address(context.Background(), addrStub{pub: pub}, "tellor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(addr, "tellor1") {
		t.Fatalf("address %q does not carry the requested prefix", addr)
	}

	if _, err := Bech32Address(context.Background(), addrStub{pub: pub}, ""); err == nil {
		t.Fatal("empty prefix must be rejected")
	}
	if _, err := Bech32Address(context.Background(), addrStub{pub: pub[:20]}, "tellor"); err == nil {
		t.Fatal("wrong-length key must be rejected")
	}
}
