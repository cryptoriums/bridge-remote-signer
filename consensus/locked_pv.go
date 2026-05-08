package consensus

import (
	"sync"

	"github.com/cometbft/cometbft/crypto"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// LockedPrivValidator serializes access to a PrivValidator so two CometBFT
// nodes (primary + standby) can share one signing key and FilePV state safely.
type LockedPrivValidator struct {
	mu sync.Mutex
	pv types.PrivValidator
}

func NewLockedPrivValidator(pv types.PrivValidator) *LockedPrivValidator {
	return &LockedPrivValidator{pv: pv}
}

func (l *LockedPrivValidator) GetPubKey() (crypto.PubKey, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pv.GetPubKey()
}

func (l *LockedPrivValidator) SignVote(chainID string, vote *cmtproto.Vote) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pv.SignVote(chainID, vote)
}

func (l *LockedPrivValidator) SignProposal(chainID string, proposal *cmtproto.Proposal) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pv.SignProposal(chainID, proposal)
}
