package dtls

import (
	"bytes"
	"context"

	"github.com/zjw1111/DTLShps/pkg/crypto/prf"
	"github.com/zjw1111/DTLShps/pkg/protocol"
	"github.com/zjw1111/DTLShps/pkg/protocol/alert"
	"github.com/zjw1111/DTLShps/pkg/protocol/handshake"
	"github.com/zjw1111/DTLShps/pkg/protocol/recordlayer"
)

func flight2Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert.Alert, error) {
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence,
		handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
	)
	if !ok {
		// Client may retransmit the first ClientHello when HelloVerifyRequest is dropped.
		// Parse as flight 0 in this case.
		return flight0Parse(ctx, c, state, cache, cfg)
	}

	var clientHello *handshake.MessageClientHello

	// Validate type
	if clientHello, ok = msgs[handshake.TypeClientHello].(*handshake.MessageClientHello); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !clientHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
	}

	if len(clientHello.Cookie) == 0 {
		return 0, nil, nil
	}
	if !bytes.Equal(state.cookie, clientHello.Cookie) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, errCookieMismatch
	}

	if cfg.DTLShps && !cfg.SkipHelloVerify {
		seq, msgs, ok = cache.fullPullMap(seq,
			handshakeCachePullRule{handshake.TypeEncryptedKey, cfg.initialEpoch, true, false},
		)
		if !ok {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoEncryptedKey}, errInvalidEncryptedKey
		}
		if EncryptedKey, ok := msgs[handshake.TypeEncryptedKey].(*handshake.MessageEncryptedKey); !ok || len(EncryptedKey.EncryptedKey) == 0 {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoEncryptedKey}, errInvalidEncryptedKey
		} else {
			if psk, err := cfg.localPSKCallback(cfg.localPSKIdentityHint); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			} else {
				nonce := state.remoteRandom.MarshalFixed()
				state.preMasterSecret = prf.DTLShpsPreMasterSecret(psk, nonce, EncryptedKey.EncryptedKey)
			}
		}
	}
	state.handshakeRecvSequence = seq

	return flight4, nil, nil
}

func flight2Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert.Alert, error) {
	state.handshakeSendSequence = 0
	return []*packet{
		{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageHelloVerifyRequest{
						Version: protocol.Version1_2,
						Cookie:  state.cookie,
					},
				},
			},
		},
	}, nil, nil
}
