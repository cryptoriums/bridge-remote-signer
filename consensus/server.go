package consensus

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/types"
)

// MaxRemoteSignerMsgSize is the max decoded privval frame (CometBFT default).
const MaxRemoteSignerMsgSize = 1024 * 10

// RunDialClient maintains a TCP+SecretConnection to a CometBFT node's
// priv_validator_laddr and serves privval requests until disconnect, then
// reconnects. Multiple RunDialClient goroutines may share the same PrivValidator
// if it is wrapped with LockedPrivValidator.
func RunDialClient(
	ctx context.Context,
	targetAddr string,
	chainID string,
	connPrivKey crypto.PrivKey,
	pv types.PrivValidator,
	handler privval.ValidationRequestHandlerFunc,
	logger log.Logger,
) {
	log := logger.With("remote", targetAddr)
	backoff := time.Second
	dialer := privval.DialTCPFn(targetAddr, 8*time.Second, connPrivKey)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := dialer()
		if err != nil {
			log.Error("privval dial failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}

		log.Info("privval connected")
		serveConn(ctx, conn, chainID, pv, handler, log)
		_ = conn.Close()
		log.Info("privval connection closed, reconnecting")

		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func serveConn(
	ctx context.Context,
	conn net.Conn,
	chainID string,
	pv types.PrivValidator,
	handler privval.ValidationRequestHandlerFunc,
	logger log.Logger,
) {
	rd := protoio.NewDelimitedReader(conn, MaxRemoteSignerMsgSize)
	wr := protoio.NewDelimitedWriter(conn)
	deadline := 8 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(deadline))
		var req privvalproto.Message
		_, err := rd.ReadMsg(&req)
		if err != nil {
			if err != io.EOF {
				logger.Error("privval read", "err", err)
			}
			return
		}

		res, handleErr := handler(pv, req, chainID)
		if handleErr != nil {
			logger.Debug("privval handler", "err", handleErr)
		}

		_ = conn.SetWriteDeadline(time.Now().Add(deadline))
		if _, err := wr.WriteMsg(&res); err != nil {
			logger.Error("privval write", "err", err)
			return
		}
	}
}
