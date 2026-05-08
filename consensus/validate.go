package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

const (
	maxChainIDLen = 64
)

var (
	errOversizedChainID = errors.New("chain_id exceeds maximum length")
	errEmptyChainID     = errors.New("chain_id is empty")
)

func validateRequestChainID(id string) error {
	if len(id) == 0 {
		return errEmptyChainID
	}
	if len(id) > maxChainIDLen {
		return errOversizedChainID
	}
	if strings.ContainsRune(id, 0) {
		return fmt.Errorf("chain_id contains NUL")
	}
	return nil
}

// ValidateSignVoteRequest checks structure before signing. The vote may have an
// empty signature (filled by the signer).
func ValidateSignVoteRequest(vote *cmtproto.Vote, expectAddr []byte) error {
	if vote == nil {
		return errors.New("nil vote")
	}
	if !types.IsVoteTypeValid(vote.Type) {
		return fmt.Errorf("invalid vote type %d", vote.Type)
	}
	if vote.Height <= 0 {
		return errors.New("vote height must be positive")
	}
	if vote.Round < 0 {
		return errors.New("negative vote round")
	}
	if vote.ValidatorIndex < 0 {
		return errors.New("negative validator index")
	}
	if len(expectAddr) > 0 {
		if len(vote.ValidatorAddress) != len(expectAddr) {
			return fmt.Errorf("validator address length %d, expected %d", len(vote.ValidatorAddress), len(expectAddr))
		}
		if !bytes.Equal(vote.ValidatorAddress, expectAddr) {
			return errors.New("validator address does not match signer key")
		}
	}
	bid, err := types.BlockIDFromProto(&vote.BlockID)
	if err != nil {
		return fmt.Errorf("block_id: %w", err)
	}
	if !bid.IsZero() && !bid.IsComplete() {
		return fmt.Errorf("block_id must be nil or complete, got partial id")
	}
	if len(vote.Extension) > types.MaxVoteExtensionSize {
		return fmt.Errorf("vote extension exceeds max size %d", types.MaxVoteExtensionSize)
	}
	if vote.Type != cmtproto.PrecommitType || bid.IsZero() {
		if len(vote.Extension) > 0 {
			return errors.New("vote extension only allowed on non-nil precommit")
		}
		if len(vote.ExtensionSignature) > 0 {
			return errors.New("extension signature only allowed on non-nil precommit")
		}
	}
	return nil
}

// ValidateSignProposalRequest validates an unsigned proposal (signature may be empty).
func ValidateSignProposalRequest(prop *cmtproto.Proposal) error {
	if prop == nil {
		return errors.New("nil proposal")
	}
	if prop.Type != cmtproto.ProposalType {
		return fmt.Errorf("invalid proposal type %d", prop.Type)
	}
	if prop.Height < 0 {
		return errors.New("negative proposal height")
	}
	if prop.Round < 0 {
		return errors.New("negative proposal round")
	}
	if prop.PolRound < -1 {
		return errors.New("invalid POL round")
	}
	bid, err := types.BlockIDFromProto(&prop.BlockID)
	if err != nil {
		return fmt.Errorf("block_id: %w", err)
	}
	if !bid.IsComplete() {
		return errors.New("proposal requires complete block_id")
	}
	return nil
}
