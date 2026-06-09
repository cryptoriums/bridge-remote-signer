package consensus

import (
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// These tests extend the double-sign coverage with additional equivocation
// scenarios beyond the existing same-height/different-hash prevote case.
// Double-signing carries the harshest slashing penalty (~50% of stake), so the
// signer must refuse to produce two conflicting signatures for the same
// height/round/step under every scenario below.

// hash32 returns a deterministic 32-byte hash seeded by b.
func hash32(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b + byte(i)
	}
	return h
}

func blockIDOf(b byte) cmtproto.BlockID {
	h := hash32(b)
	return cmtproto.BlockID{Hash: h, PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: h}}
}

// newFilePVAtPath builds a FilePV whose key+state live at a STABLE path (not a
// fresh TempDir each call), so a second FilePV can reload the same state file —
// needed to simulate a signer restart.
func newFilePVAtPath(t *testing.T, dir string) *privval.FilePV {
	t.Helper()
	keyFile := filepath.Join(dir, "key.json")
	stateFile := filepath.Join(dir, "state.json")
	pv := privval.NewFilePV(ed25519.GenPrivKey(), keyFile, stateFile)
	pv.Save()
	return pv
}

// reloadFilePV loads an existing FilePV from the same key+state files (restart).
func reloadFilePV(t *testing.T, dir string) *privval.FilePV {
	t.Helper()
	keyFile := filepath.Join(dir, "key.json")
	stateFile := filepath.Join(dir, "state.json")
	return privval.LoadFilePV(keyFile, stateFile)
}

func voteOf(typ cmtproto.SignedMsgType, height int64, round int32, addr []byte, bid cmtproto.BlockID) *cmtproto.Vote {
	return &cmtproto.Vote{
		Type:             typ,
		Height:           height,
		Round:            round,
		BlockID:          bid,
		ValidatorAddress: addr,
		ValidatorIndex:   0,
	}
}

//  1. PRECOMMIT double-sign: signing two different blocks as precommit at the
//     same height/round must be rejected. (Existing tests cover prevote; precommit
//     is the more dangerous, directly-slashable equivocation.)
func TestDoubleSign_PrecommitConflictRejected(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))
	addr := mustAddr(t, lpv)

	if err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 100, 0, addr, blockIDOf(1))); err != nil {
		t.Fatalf("first precommit sign failed: %v", err)
	}
	err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 100, 0, addr, blockIDOf(2)))
	if err == nil {
		t.Fatal("DOUBLE SIGN: second conflicting precommit at same H/R was signed")
	}
}

//  2. NIL vs non-NIL at the same height/round: after precommitting a real block,
//     a precommit for nil (empty BlockID) at the same H/R is a conflicting vote
//     and must be rejected — and vice versa.
func TestDoubleSign_NilThenBlockRejected(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))
	addr := mustAddr(t, lpv)

	// Precommit a real block first.
	if err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 200, 0, addr, blockIDOf(7))); err != nil {
		t.Fatalf("first sign (block) failed: %v", err)
	}
	// Now a nil precommit at the same H/R conflicts.
	nilVote := voteOf(cmtproto.PrecommitType, 200, 0, addr, cmtproto.BlockID{})
	if err := lpv.SignVote("tellor-1", nilVote); err == nil {
		t.Fatal("DOUBLE SIGN: nil precommit accepted after block precommit at same H/R")
	}
}

//  3. HRS must not go backwards: after signing at a higher round, signing a vote
//     at a LOWER round for the same height must be rejected (stale/replayed).
func TestDoubleSign_LowerRoundAfterHigherRejected(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))
	addr := mustAddr(t, lpv)

	if err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 300, 5, addr, blockIDOf(3))); err != nil {
		t.Fatalf("sign at round 5 failed: %v", err)
	}
	err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 300, 2, addr, blockIDOf(4)))
	if err == nil {
		t.Fatal("HRS regression: vote at lower round accepted after higher round")
	}
}

//  4. RESTART must not enable a double-sign: sign at height H, drop the in-memory
//     FilePV, reload from the SAME state file (simulating a signer/container
//     restart), then attempt to sign a conflicting block at H. The persisted
//     state must still reject it. This is the critical real-world scenario.
func TestDoubleSign_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	// First instance signs a block at height 400.
	pv1 := newFilePVAtPath(t, dir)
	lpv1 := NewLockedPrivValidator(pv1)
	addr := mustAddr(t, lpv1)
	if err := lpv1.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 400, 0, addr, blockIDOf(9))); err != nil {
		t.Fatalf("first instance sign failed: %v", err)
	}

	// "Restart": reload FilePV from the same key+state files.
	pv2 := reloadFilePV(t, dir)
	lpv2 := NewLockedPrivValidator(pv2)

	// Conflicting block at the same height must be rejected by the persisted state.
	err := lpv2.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 400, 0, addr, blockIDOf(10)))
	if err == nil {
		t.Fatal("DOUBLE SIGN ACROSS RESTART: reloaded signer signed a conflicting block at the same height")
	}
}

//  5. Proposal vs proposal conflict at same H/R must be rejected (round-leader
//     equivocation). Existing TestSignProposal_DoubleSignRejected covers a case;
//     this asserts it independently with the locked PV directly.
func TestDoubleSign_ProposalConflictRejected(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))

	propA := &cmtproto.Proposal{Type: cmtproto.ProposalType, Height: 500, Round: 0, PolRound: -1, BlockID: blockIDOf(11)}
	propB := &cmtproto.Proposal{Type: cmtproto.ProposalType, Height: 500, Round: 0, PolRound: -1, BlockID: blockIDOf(12)}

	if err := lpv.SignProposal("tellor-1", propA); err != nil {
		t.Fatalf("first proposal sign failed: %v", err)
	}
	if err := lpv.SignProposal("tellor-1", propB); err == nil {
		t.Fatal("DOUBLE SIGN: second conflicting proposal at same H/R was signed")
	}
}

//  6. Cross-chain safety: the same H/R/block signed once must not be re-signed
//     under a DIFFERENT chain ID without the state guard catching the HRS reuse.
//     (Idempotent identical re-sign on the SAME chain is allowed; a different
//     chain id at the same HRS with a different block is a conflict.)
func TestDoubleSign_DifferentChainSameHRSConflict(t *testing.T) {
	lpv := NewLockedPrivValidator(newFilePVAtPath(t, t.TempDir()))
	addr := mustAddr(t, lpv)

	if err := lpv.SignVote("tellor-1", voteOf(cmtproto.PrecommitType, 600, 0, addr, blockIDOf(13))); err != nil {
		t.Fatalf("first sign failed: %v", err)
	}
	// Same HRS, different block, different chain id — FilePV tracks HRS regardless
	// of chain id, so this conflicting vote must be rejected.
	err := lpv.SignVote("some-other-chain", voteOf(cmtproto.PrecommitType, 600, 0, addr, blockIDOf(14)))
	if err == nil {
		t.Fatal("DOUBLE SIGN: conflicting vote at same HRS accepted under a different chain id")
	}
}

func mustAddr(t *testing.T, lpv *LockedPrivValidator) []byte {
	t.Helper()
	pk, err := lpv.GetPubKey()
	if err != nil {
		t.Fatalf("GetPubKey: %v", err)
	}
	return pk.Address()
}
