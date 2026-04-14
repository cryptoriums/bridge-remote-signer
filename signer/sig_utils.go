package signer

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// This whole file is about translating signatures. HSMs (hardware security modules)
// produce signatures in a standard format called DER. Ethereum expects a different
// format, a flat 65 bytes: R (32 bytes) then S (32 bytes) then V (1 byte) all
// glued together back to back. This file bridges that gap.

// Every ECDSA signature is just two big numbers: R and S. The elliptic curve
// used by Ethereum (secp256k1) has an "order" N, think of it as the total number
// of points on the curve. This value is half of N. We need it because Ethereum
// requires S to be in the lower half of possible values (see rsToEthSig for why).
//
// Rsh means "right shift." Shifting binary bits one position to the right is the
// same as dividing by 2. So secp256k1.S256().N is the full curve order, and
// Rsh(..., 1) gives us half of that.
var secp256k1HalfN = new(big.Int).Rsh(secp256k1.S256().N, 1)

// When an HSM signs something with ECDSA, it hands back R and S wrapped in a
// binary encoding called ASN.1 DER (Distinguished Encoding Rules). This struct
// mirrors that structure so Go's asn1 package can decode it.
type ecdsaDERSig struct {
	R, S *big.Int
}

// parseDERSignature opens the DER "envelope" and pulls out R and S.
// Think of DER as a formal package with headers and length tags.
// This function strips all that away and gives you the raw numbers.
func parseDERSignature(der []byte) (*big.Int, *big.Int, error) {
	var sig ecdsaDERSig
	// asn1.Unmarshal knows the DER encoding rules and does the heavy lifting.
	// The underscore (_) on the left is Go's way of saying "this function returns
	// two things but I only care about the second one (the error)." The first
	// return value (number of bytes read) gets thrown away.
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		// %w means "wrap" this error. It lets callers further up the chain
		// inspect the original error if they need to.
		return nil, nil, fmt.Errorf("failed to unmarshal DER signature: %w", err)
	}
	// Sanity check: a valid ECDSA signature always has both R and S.
	if sig.R == nil || sig.S == nil {
		return nil, nil, errors.New("DER signature has nil R or S")
	}
	return sig.R, sig.S, nil
}

// rsToEthSig takes raw R and S values and produces the 65 byte signature Ethereum needs.
//
// Some backends (like YubiHSM) give us R and S directly instead of DER,
// so this function is called directly by them. The Fortanix backend
// goes through derToEthSig, which calls this after unwrapping DER.
func rsToEthSig(r, s *big.Int, msg, compressedPubKey []byte) ([]byte, error) {
	// Step 1: Lower S normalization (EIP 2)
	//
	// Here's the deal: for any valid signature (R, S), the pair (R, N minus S) is
	// ALSO a valid signature for the same message. Every signature has a "twin."
	// This is a problem called "transaction malleability" where someone could take
	// your signed transaction, flip S to its twin, and it would still verify
	// but produce a different transaction hash. That breaks anything tracking
	// transactions by hash and thats why Ethereum had this weird rule that S
	// must be in the lower half of possible values and it works.
	//
	// EIP 2 fixes this by requiring S to always be in the lower half (no more than N/2).
	// If S is in the upper half, we flip it to its twin (N minus S), which is
	// guaranteed to be in the lower half. This makes signatures unique.
	curveN := secp256k1.S256().N
	// .Cmp means "compare." It returns a positive number if s is greater,
	// zero if equal, negative if less. So "> 0" means "s is bigger than halfN."
	if s.Cmp(secp256k1HalfN) > 0 {
		// This computes curveN minus s, giving us the
		// lower twin of S.
		s = new(big.Int).Sub(curveN, s)
	}

	// Step 2: Pack R and S into a flat 64 byte layout
	//
	// Ethereum expects R and S as exactly 32 bytes each, but big.Int.Bytes()
	// returns only the bytes needed (no leading zeros). If R is, say, 30 bytes,
	// we need to pad with 2 zero bytes on the left so it fills its 32 byte slot.
	// The copy trick here does that: it writes the bytes aligned to the right of
	// the 32 byte window, leaving any unused leading bytes as zero.
	sig := make([]byte, 65)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	// The [32-len(rBytes):32] is a "slice expression." So if rBytes is 30 bytes
	// long, this says "start at index 2, end at index 32" which is a 30 byte
	// window. The first 2 bytes (index 0 and 1) stay as zeros, giving us
	// the left padding we need.
	copy(sig[32-len(rBytes):32], rBytes) // R occupies bytes 0 to 31
	copy(sig[64-len(sBytes):64], sBytes) // S occupies bytes 32 to 63

	// Step 3: Figure out the recovery byte V
	//
	// V is what makes Ethereum signatures special. Normal ECDSA verification
	// requires knowing the public key upfront. But Ethereum's ecrecover can
	// work backwards: given the signature and the message, it recovers the
	// public key. The catch is that elliptic curve math always produces TWO
	// candidate keys. V (0 or 1) tells ecrecover which one is correct.
	// sig[:64] is another slice expression. The first 64 bytes
	// of sig" which is just the R and S portion, without the V byte at the end.
	v, err := recoverV(msg, sig[:64], compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute recovery byte: %w", err)
	}

	// Ethereum uses V=27 or V=28 instead of 0 or 1. Not sure why just the number
	// Vitalik picked I guess.
	sig[64] = v + 27

	return sig, nil
}

// recoverV figures out the correct V value (0 or 1) by force.
//
// Since V can only be two values, we just try both and see which one
// recovers a public key matching the one we expect. It's like trying
// both keys on a lock. One of them will work.
func recoverV(msg, rsSig, compressedPubKey []byte) (byte, error) {
	for v := range byte(2) {
		// Try a 65 byte signature with this V value.
		candidate := make([]byte, 65)
		copy(candidate, rsSig)
		candidate[64] = v

		// Ecrecover takes (message_hash, signature) and returns the public key
		// that produced this signature. If V is wrong, this may error or
		// return the wrong key.
		recovered, err := crypto.Ecrecover(msg, candidate)
		if err != nil {
			continue // wrong V, try the other one
		}

		// Ecrecover returns an UNCOMPRESSED public key: 65 bytes
		// formatted as: 0x04 prefix, then X (32 bytes), then Y (32 bytes)
		// all placed back to back. 0x04 is just a tag byte that means
		// "this is an uncompressed point."
		//
		// We need to compress it to compare against our expected key.
		// Compressed format is just X plus a single byte indicating
		// which of two possible Y values to use, 33 bytes total.
		if len(recovered) == 65 {
			// recovered[1:33] means "bytes from index 1 up to but not including 33."
			// This skips the 0x04 tag at index 0 and grabs the 32 byte X coordinate.
			// recovered[33:65] grabs the 32 byte Y coordinate right after X.
			x := new(big.Int).SetBytes(recovered[1:33])
			y := new(big.Int).SetBytes(recovered[33:65])
			compressed := elliptic.MarshalCompressed(secp256k1.S256(), x, y)
			if bytes.Equal(compressed, compressedPubKey) {
				return v, nil // found the right V
			}
		}
	}
	// If we get here, something is seriously wrong. The signature doesn't
	// match the public key we expected. Could mean the wrong key was used
	// to sign, or the message hash doesn't match what was actually signed.
	return 0, errors.New("neither v=0 nor v=1 recovered the expected public key")
}

func derToEthSig(der, msg, compressedPubKey []byte) ([]byte, error) {
	r, s, err := parseDERSignature(der)
	if err != nil {
		return nil, err
	}
	return rsToEthSig(r, s, msg, compressedPubKey)
}
