package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ErrReplayGuardRejected is returned when a checkpoint's validator_timestamp is not
// greater than the last signed one. This is EXPECTED steady-state behavior: the same
// valset checkpoint is resent every block until the valset changes (a >5% power shift or
// the ~2-week refresh), so the signer signs it once and rejects the repeats. Callers
// should treat this as a normal (debug) event, not an alarming error.
//
// Rejecting the repeats is only safe while the signature from the FIRST signing reaches
// the chain. If it does not — the vote extension carrying it is lost to a node restart, a
// missed block, or a signer migration — the node re-asks every block forever and that
// checkpoint stays permanently unsigned by this validator. Observed on mainnet: the
// 2026-08-06 checkpoint went unsigned for 7 days at ~2,700 rejected requests/hour.
// CachedSignature closes that hole by replaying the stored signature for a byte-identical
// repeat instead of rejecting it.
var ErrReplayGuardRejected = errors.New("checkpoint replay guard rejected")

// checkpointReplayGuard enforces a monotonic high-water mark on the bridge
// checkpoint validator_timestamp so a replayed (or out-of-order) checkpoint
// request can never be re-signed. The high-water value is persisted to a small
// file (atomically: temp-file + rename) so the guard survives restarts.
//
// Alongside the high-water mark it memoizes the checkpoint that was signed at that
// timestamp and the resulting signature, so an identical repeat can be answered from
// the memo rather than rejected (see CachedSignature). The memo holds no secret: the
// checkpoint and its signature are both published on chain.
//
// If statePath is empty the guard keeps its state in memory only (used in tests and
// when no consensus state dir is configured).
type checkpointReplayGuard struct {
	mu        sync.Mutex
	statePath string
	highWater uint64
	loaded    bool

	// signedCheckpoint/signedSignature memoize the result of the signing that
	// advanced highWater. Both are nil until RecordSignature is called, which is
	// also the case after loading a legacy bare-integer state file.
	signedCheckpoint []byte
	signedSignature  []byte
}

// guardState is the on-disk representation. It supersedes the original bare
// decimal-integer file, which is still accepted on read for backward compatibility.
type guardState struct {
	HighWater  uint64 `json:"high_water"`
	Checkpoint string `json:"checkpoint,omitempty"` // hex, 32 bytes
	Signature  string `json:"signature,omitempty"`  // hex, 64 bytes
}

// newCheckpointReplayGuard creates a guard backed by statePath. If statePath is
// non-empty its current contents (if any) seed the high-water mark and, when the
// file is in the JSON format, the memoized signature.
func newCheckpointReplayGuard(statePath string) (*checkpointReplayGuard, error) {
	g := &checkpointReplayGuard{statePath: statePath}
	if statePath == "" {
		g.loaded = true
		return g, nil
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			g.loaded = true
			return g, nil
		}
		return nil, fmt.Errorf("read checkpoint replay guard %q: %w", statePath, err)
	}

	raw := strings.TrimSpace(string(data))
	if strings.HasPrefix(raw, "{") {
		var st guardState
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			return nil, fmt.Errorf("parse checkpoint replay guard %q: %w", statePath, err)
		}
		ckpt, err := decodeOptionalHex(st.Checkpoint, 32, "checkpoint", statePath)
		if err != nil {
			return nil, err
		}
		sig, err := decodeOptionalHex(st.Signature, 64, "signature", statePath)
		if err != nil {
			return nil, err
		}
		g.highWater = st.HighWater
		// Only keep the memo when BOTH halves are present; a half-written memo must
		// never be replayed.
		if ckpt != nil && sig != nil {
			g.signedCheckpoint = ckpt
			g.signedSignature = sig
		}
		g.loaded = true
		return g, nil
	}

	// Legacy format: a bare decimal high-water mark, with no memoized signature.
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse checkpoint replay guard %q: %w", statePath, err)
	}
	g.highWater = v
	g.loaded = true
	return g, nil
}

// decodeOptionalHex decodes s as hex and asserts it is exactly want bytes. An empty
// string decodes to nil, which callers treat as "no memo".
func decodeOptionalHex(s string, want int, field, path string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("parse checkpoint replay guard %q: %s: %w", path, field, err)
	}
	if len(b) != want {
		return nil, fmt.Errorf("parse checkpoint replay guard %q: %s must be %d bytes, got %d", path, field, want, len(b))
	}
	return b, nil
}

// CachedSignature returns the signature previously produced for checkpoint at ts, if
// the guard holds one. It answers only an EXACT repeat: the timestamp must equal the
// high-water mark and the checkpoint must be byte-identical to the one signed then.
// Any other combination returns false so the caller keeps failing closed.
//
// This is safe because the caller has already recomputed the checkpoint from the
// structured request and asserted it equals the request's expected_checkpoint, so a hit
// here means the message is the very one that produced this signature — returning it
// re-sends known-public bytes and signs nothing new.
func (g *checkpointReplayGuard) CachedSignature(ts uint64, checkpoint []byte) ([]byte, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.loaded || ts != g.highWater {
		return nil, false
	}
	if g.signedCheckpoint == nil || g.signedSignature == nil {
		return nil, false
	}
	if !bytes.Equal(g.signedCheckpoint, checkpoint) {
		return nil, false
	}
	out := make([]byte, len(g.signedSignature))
	copy(out, g.signedSignature)
	return out, true
}

// RecordSignature memoizes the signature produced for checkpoint at ts so a later
// identical request can be answered without re-signing. It is called only after a
// successful signing that advanced the high-water mark to ts; a mismatch means the
// caller advanced past this timestamp meanwhile, so the memo is left alone.
//
// A persistence failure is returned but is not fatal to the signing that just
// succeeded: the caller logs it and still returns the fresh signature.
func (g *checkpointReplayGuard) RecordSignature(ts uint64, checkpoint, sig []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if ts != g.highWater {
		return nil
	}
	g.signedCheckpoint = append([]byte(nil), checkpoint...)
	g.signedSignature = append([]byte(nil), sig...)

	if g.statePath == "" {
		return nil
	}
	return g.persistLocked()
}

// CheckAndAdvance rejects ts if it is <= the persisted high-water mark, then
// atomically persists ts as the new high-water mark. Returns an error (and
// advances nothing) on replay/out-of-order or on a persistence failure — the
// caller must FAIL CLOSED and sign nothing if this returns non-nil.
func (g *checkpointReplayGuard) CheckAndAdvance(ts uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.loaded && ts <= g.highWater {
		return fmt.Errorf("%w: validator_timestamp %d is not greater than last signed %d", ErrReplayGuardRejected, ts, g.highWater)
	}

	// Advancing to a new timestamp invalidates the previous memo: it belongs to the
	// checkpoint we are moving past, and must never answer a request for this one.
	prevCheckpoint, prevSignature := g.signedCheckpoint, g.signedSignature
	prevHighWater := g.highWater
	g.highWater = ts
	g.signedCheckpoint, g.signedSignature = nil, nil

	if g.statePath == "" {
		return nil
	}
	if err := g.persistLocked(); err != nil {
		// Roll back so memory never claims a high-water mark that is not on disk.
		g.highWater = prevHighWater
		g.signedCheckpoint, g.signedSignature = prevCheckpoint, prevSignature
		return fmt.Errorf("persist checkpoint replay guard: %w", err)
	}
	return nil
}

// persistLocked atomically writes the current state. Callers must hold g.mu.
func (g *checkpointReplayGuard) persistLocked() error {
	st := guardState{HighWater: g.highWater}
	if g.signedCheckpoint != nil && g.signedSignature != nil {
		st.Checkpoint = hex.EncodeToString(g.signedCheckpoint)
		st.Signature = hex.EncodeToString(g.signedSignature)
	}
	blob, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshal guard state: %w", err)
	}
	return writeBytesAtomic(g.statePath, blob)
}

// writeBytesAtomic writes b to path atomically by writing a temp file in the
// same directory, fsyncing it, renaming it into place (overwriting), then
// fsyncing the parent directory. Unlike WriteNewFileAtomic this intentionally
// overwrites the previous value (the high-water mark advances).
func writeBytesAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}

	f, err := os.CreateTemp(dir, ".ckpt-hw-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file to %q: %w", path, err)
	}

	return syncDirBestEffort(dir)
}

// syncDirBestEffort fsyncs dir so the rename is durable across a crash.
func syncDirBestEffort(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %q for fsync: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir %q: %w", dir, err)
	}
	return nil
}
