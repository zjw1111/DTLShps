package dtls

import (
	"context"

	"github.com/zjw1111/DTLShps/pkg/crypto/prf"
	"github.com/zjw1111/DTLShps/pkg/protocol"
	"github.com/zjw1111/DTLShps/pkg/protocol/alert"
	"github.com/zjw1111/DTLShps/pkg/protocol/handshake"
	"github.com/zjw1111/DTLShps/pkg/protocol/recordlayer"
)

func flight6Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert.Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence-1,
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	// Other party retransmitted the last flight.
	return flight6, nil, nil
}

func flight6Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert.Alert, error) {
	var pkts []*packet

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &protocol.ChangeCipherSpec{},
			},
		})

	// NOTE: 发送 server Finish
	if len(state.localVerifyData) == 0 {
		var plainText []byte
		if cfg.DTLShps {
			plainText = cache.pullAndMerge(cfg.DTLShps,
				handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
				handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, false},
				handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
				handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
			)
		} else {
			plainText = cache.pullAndMerge(cfg.DTLShps,
				handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
				handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
				handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, false, false},
				handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, false},
				handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, false},
				handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
				handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, true, false},
				handshakeCachePullRule{handshake.TypeClientKeyExchange, cfg.initialEpoch, true, false},
				handshakeCachePullRule{handshake.TypeCertificateVerify, cfg.initialEpoch, true, false},
				handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
			)
		}

		var err error
		state.localVerifyData, err = prf.VerifyDataServer(state.masterSecret, plainText, state.cipherSuite.HashFunc())
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
					Epoch:   1,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageFinished{
						VerifyData: state.localVerifyData,
					},
				},
			},
			// when use controller, the controller will send one more message, so MessageSequence needs to add one
			addOneMessageSequence:    cfg.DTLShps && !cfg.TestWithoutController,
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		},
	)
	return pkts, nil, nil
}
