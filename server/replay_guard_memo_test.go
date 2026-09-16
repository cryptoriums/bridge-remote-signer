package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func mustGuard(t *testing.T, path string) *checkpointReplayGuard {
	t.Helper()
	g, err := newCheckpointReplayGuard(path)
	if err != nil {
		t.Fatalf("newCheckpointReplayGuard: %v", err)
	}
	return g
}

func ckpt(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
func sig(b byte) []byte  { return bytes.Repeat([]byte{b}, 64) }

// An exact repeat of the checkpoint that was signed is answered from the memo.
// This is the case that was hanging mainnet: the node re-asks every block and,
// without the memo, never gets a signature back.
func TestCachedSignature_ExactRepeatIsServed(t *testing.T) {
	g := mustGuard(t, filepath.Join(t.TempDir(), "hw"))

	if err := g.CheckAndAdvance(100); err != nil {
		t.Fatalf("CheckAndAdvance: %v", err)
	}
	if err := g.RecordSignature(100, ckpt(0xAA), sig(0x11)); err != nil {
		t.Fatalf("RecordSignature: %v", err)
	}

	// The repeat is still rejected by the guard proper...
	if err := g.CheckAndAdvance(100); err == nil {
		t.Fatal("CheckAndAdvance(100) must still reject a repeat")
	}
	// ...but the memo answers it.
	got, ok := g.CachedSignature(100, ckpt(0xAA))
	if !ok {
		t.Fatal("CachedSignature: want hit for the exact checkpoint")
	}
	if !bytes.Equal(got, sig(0x11)) {
		t.Fatalf("CachedSignature returned %x, want %x", got, sig(0x11))
	}
}

// The memo must never answer for a DIFFERENT checkpoint at the same timestamp.
// That combination is an equivocation attempt and must keep failing closed.
func TestCachedSignature_DifferentCheckpointSameTimestampIsRefused(t *testing.T) {
	g := mustGuard(t, filepath.Join(t.TempDir(), "hw"))
	if err := g.CheckAndAdvance(100); err != nil {
		t.Fatalf("CheckAndAdvance: %v", err)
	}
	if err := g.RecordSignature(100, ckpt(0xAA), sig(0x11)); err != nil {
		t.Fatalf("RecordSignature: %v", err)
	}

	if _, ok := g.CachedSignature(100, ckpt(0xBB)); ok {
		t.Fatal("CachedSignature must refuse a different checkpoint at the same timestamp")
	}
}

// An older timestamp must never be served from the memo, even with a checkpoint
// that was legitimately signed at some point.
func TestCachedSignature_OlderTimestampIsRefused(t *testing.T) {
	g := mustGuard(t, filepath.Join(t.TempDir(), "hw"))
	if err := g.CheckAndAdvance(100); err != nil {
		t.Fatalf("CheckAndAdvance: %v", err)
	}
	if err := g.RecordSignature(100, ckpt(0xAA), sig(0x11)); err != nil {
		t.Fatalf("RecordSignature: %v", err)
	}
	if err := g.CheckAndAdvance(200); err != nil {
		t.Fatalf("CheckAndAdvance(200): %v", err)
	}

	if _, ok := g.CachedSignature(100, ckpt(0xAA)); ok {
		t.Fatal("CachedSignature must refuse a superseded timestamp")
	}
}

// Advancing to a new timestamp drops the previous memo, so the old signature can
// never be replayed against the new checkpoint.
func TestCheckAndAdvance_ClearsPreviousMemo(t *testing.T) {
	g := mustGuard(t, filepath.Join(t.TempDir(), "hw"))
	if err := g.CheckAndAdvance(100); err != nil {
		t.Fatalf("CheckAndAdvance: %v", err)
	}
	if err := g.RecordSignature(100, ckpt(0xAA), sig(0x11)); err != nil {
		t.Fatalf("RecordSignature: %v", err)
	}
	if err := g.CheckAndAdvance(200); err != nil {
		t.Fatalf("CheckAndAdvance(200): %v", err)
	}

	if _, ok := g.CachedSignature(200, ckpt(0xAA)); ok {
		t.Fatal("memo from timestamp 100 must not answer at timestamp 200")
	}
}

// The memo survives a restart — the failure that stranded mainnet was a restart
// losing the only copy of the signature.
func TestCachedSignature_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hw")

	g := mustGuard(t, path)
	if err := g.CheckAndAdvance(100); err != nil {
		t.Fatalf("CheckAndAdvance: %v", err)
	}
	if err := g.RecordSignature(100, ckpt(0xAA), sig(0x11)); err != nil {
		t.Fatalf("RecordSignature: %v", err)
	}

	reloaded := mustGuard(t, path)
	got, ok := reloaded.CachedSignature(100, ckpt(0xAA))
	if !ok {
		t.Fatal("memo must survive a restart")
	}
	if !bytes.Equal(got, sig(0x11)) {
		t.Fatalf("reloaded memo = %x, want %x", got, sig(0x11))
	}
	if reloaded.highWater != 100 {
		t.Fatalf("reloaded highWater = %d, want 100", reloaded.highWater)
	}
}

// A state file written by the previous version is a bare decimal integer. It must
// still load, keep protecting, and simply carry no memo.
func TestNewGuard_ReadsLegacyIntegerFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hw")
	if err := os.WriteFile(path, []byte("12345\n"), 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}

	g := mustGuard(t, path)
	if g.highWater != 12345 {
		t.Fatalf("highWater = %d, want 12345", g.highWater)
	}
	if _, ok := g.CachedSignature(12345, ckpt(0xAA)); ok {
		t.Fatal("a legacy file carries no memo, so there is nothing to serve")
	}
	if err := g.CheckAndAdvance(12345); err == nil {
		t.Fatal("legacy high-water mark must still reject a repeat")
	}
}

// After advancing, the file is JSON and holds the memo in hex.
func TestPersist_WritesJSONWithMemo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hw")
	g := mustGuard(t, path)
	if err := g.CheckAndAdvance(777); err != nil {
		t.Fatalf("CheckAndAdvance: %v", err)
	}
	if err := g.RecordSignature(777, ckpt(0xCC), sig(0xDD)); err != nil {
		t.Fatalf("RecordSignature: %v", err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var st guardState
	if err := json.Unmarshal(blob, &st); err != nil {
		t.Fatalf("state file is not JSON: %v (%s)", err, blob)
	}
	if st.HighWater != 777 {
		t.Fatalf("HighWater = %d, want 777", st.HighWater)
	}
	if st.Checkpoint != hex.EncodeToString(ckpt(0xCC)) {
		t.Fatalf("Checkpoint = %q", st.Checkpoint)
	}
	if st.Signature != hex.EncodeToString(sig(0xDD)) {
		t.Fatalf("Signature = %q", st.Signature)
	}
}

// A half-written memo (checkpoint present, signature missing) must be discarded
// rather than half-trusted.
func TestNewGuard_RejectsHalfWrittenMemo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hw")
	blob, _ := json.Marshal(guardState{HighWater: 5, Checkpoint: hex.EncodeToString(ckpt(0xAA))})
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	g := mustGuard(t, path)
	if g.highWater != 5 {
		t.Fatalf("highWater = %d, want 5", g.highWater)
	}
	if _, ok := g.CachedSignature(5, ckpt(0xAA)); ok {
		t.Fatal("a memo missing its signature must not be served")
	}
}

// A memo whose hex is the wrong length is corruption, not a usable memo.
func TestNewGuard_RejectsWrongLengthMemo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hw")
	blob, _ := json.Marshal(guardState{
		HighWater:  5,
		Checkpoint: hex.EncodeToString([]byte{0x01, 0x02}),
		Signature:  hex.EncodeToString(sig(0x11)),
	})
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if _, err := newCheckpointReplayGuard(path); err == nil {
		t.Fatal("a wrong-length checkpoint must fail to load, not load silently")
	}
}

// RecordSignature for a timestamp that is no longer current must not overwrite the
// memo belonging to the current one.
func TestRecordSignature_IgnoresStaleTimestamp(t *testing.T) {
	g := mustGuard(t, filepath.Join(t.TempDir(), "hw"))
	if err := g.CheckAndAdvance(100); err != nil {
		t.Fatalf("CheckAndAdvance: %v", err)
	}
	if err := g.RecordSignature(100, ckpt(0xAA), sig(0x11)); err != nil {
		t.Fatalf("RecordSignature: %v", err)
	}
	if err := g.CheckAndAdvance(200); err != nil {
		t.Fatalf("CheckAndAdvance(200): %v", err)
	}
	if err := g.RecordSignature(200, ckpt(0xBB), sig(0x22)); err != nil {
		t.Fatalf("RecordSignature(200): %v", err)
	}

	// A late record for the superseded timestamp is a no-op.
	if err := g.RecordSignature(100, ckpt(0xAA), sig(0x11)); err != nil {
		t.Fatalf("RecordSignature(stale): %v", err)
	}
	got, ok := g.CachedSignature(200, ckpt(0xBB))
	if !ok || !bytes.Equal(got, sig(0x22)) {
		t.Fatal("stale RecordSignature must not disturb the current memo")
	}
}
