package consensus

import (
	"fmt"

	"github.com/cosmos/gogoproto/proto"

	"github.com/cometbft/cometbft/crypto"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	cryptoproto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/types"
)

func wrapMsg(pb proto.Message) privvalproto.Message {
	msg := privvalproto.Message{}
	switch pb := pb.(type) {
	case *privvalproto.PubKeyResponse:
		msg.Sum = &privvalproto.Message_PubKeyResponse{PubKeyResponse: pb}
	case *privvalproto.SignedVoteResponse:
		msg.Sum = &privvalproto.Message_SignedVoteResponse{SignedVoteResponse: pb}
	case *privvalproto.SignedProposalResponse:
		msg.Sum = &privvalproto.Message_SignedProposalResponse{SignedProposalResponse: pb}
	case *privvalproto.PingResponse:
		msg.Sum = &privvalproto.Message_PingResponse{PingResponse: pb}
	default:
		panic(fmt.Errorf("layer-signer: unknown wrap type %T", pb))
	}
	return msg
}

func remoteErr(desc string) *privvalproto.RemoteSignerError {
	return &privvalproto.RemoteSignerError{Code: 0, Description: desc}
}

// ValidationRequestHandler returns a privval handler with extra safety checks
// before delegating to CometBFT signing (FilePV) via DefaultValidationRequestHandler.
func ValidationRequestHandler(valAddr []byte) privval.ValidationRequestHandlerFunc {
	return func(pv types.PrivValidator, req privvalproto.Message, chainID string) (privvalproto.Message, error) {
		var res privvalproto.Message
		switch r := req.Sum.(type) {
		case *privvalproto.Message_PubKeyRequest:
			cid := r.PubKeyRequest.GetChainId()
			if err := validateRequestChainID(cid); err != nil {
				res = wrapMsg(&privvalproto.PubKeyResponse{
					PubKey: cryptoproto.PublicKey{},
					Error:  remoteErr(err.Error()),
				})
				return res, err
			}
		case *privvalproto.Message_SignVoteRequest:
			cid := r.SignVoteRequest.GetChainId()
			if err := validateRequestChainID(cid); err != nil {
				res = wrapMsg(&privvalproto.SignedVoteResponse{
					Vote:  cmtproto.Vote{},
					Error: remoteErr(err.Error()),
				})
				return res, err
			}
			if r.SignVoteRequest.Vote == nil {
				res = wrapMsg(&privvalproto.SignedVoteResponse{
					Vote:  cmtproto.Vote{},
					Error: remoteErr("nil vote in request"),
				})
				return res, fmt.Errorf("nil vote")
			}
			if err := ValidateSignVoteRequest(r.SignVoteRequest.Vote, valAddr); err != nil {
				res = wrapMsg(&privvalproto.SignedVoteResponse{
					Vote:  cmtproto.Vote{},
					Error: remoteErr(err.Error()),
				})
				return res, err
			}
		case *privvalproto.Message_SignProposalRequest:
			cid := r.SignProposalRequest.GetChainId()
			if err := validateRequestChainID(cid); err != nil {
				res = wrapMsg(&privvalproto.SignedProposalResponse{
					Proposal: cmtproto.Proposal{},
					Error:    remoteErr(err.Error()),
				})
				return res, err
			}
			if r.SignProposalRequest.Proposal == nil {
				res = wrapMsg(&privvalproto.SignedProposalResponse{
					Proposal: cmtproto.Proposal{},
					Error:    remoteErr("nil proposal in request"),
				})
				return res, fmt.Errorf("nil proposal")
			}
			if err := ValidateSignProposalRequest(r.SignProposalRequest.Proposal); err != nil {
				res = wrapMsg(&privvalproto.SignedProposalResponse{
					Proposal: cmtproto.Proposal{},
					Error:    remoteErr(err.Error()),
				})
				return res, err
			}
		}
		return privval.DefaultValidationRequestHandler(pv, req, chainID)
	}
}

// ValidatorAddressForHandler returns the consensus address for the validator key (20 bytes).
func ValidatorAddressForHandler(pv types.PrivValidator) ([]byte, error) {
	pk, err := pv.GetPubKey()
	if err != nil {
		return nil, err
	}
	return pk.Address(), nil
}

// MustPubKeyResponse is a test helper to decode pubkey response.
func MustPubKeyResponse(msg *privvalproto.Message) *privvalproto.PubKeyResponse {
	if msg == nil || msg.Sum == nil {
		return nil
	}
	if r, ok := msg.Sum.(*privvalproto.Message_PubKeyResponse); ok {
		return r.PubKeyResponse
	}
	return nil
}

// MustSignedVoteResponse unwraps SignedVoteResponse.
func MustSignedVoteResponse(msg *privvalproto.Message) *privvalproto.SignedVoteResponse {
	if msg == nil || msg.Sum == nil {
		return nil
	}
	if r, ok := msg.Sum.(*privvalproto.Message_SignedVoteResponse); ok {
		return r.SignedVoteResponse
	}
	return nil
}

// MustSignedProposalResponse unwraps SignedProposalResponse.
func MustSignedProposalResponse(msg *privvalproto.Message) *privvalproto.SignedProposalResponse {
	if msg == nil || msg.Sum == nil {
		return nil
	}
	if r, ok := msg.Sum.(*privvalproto.Message_SignedProposalResponse); ok {
		return r.SignedProposalResponse
	}
	return nil
}

// PubKeyFromResponse decodes consensus pubkey from a PubKeyResponse.
func PubKeyFromResponse(resp *privvalproto.PubKeyResponse) (crypto.PubKey, error) {
	if resp == nil || resp.Error != nil {
		return nil, fmt.Errorf("pubkey error: %v", resp)
	}
	return cryptoenc.PubKeyFromProto(resp.PubKey)
}
