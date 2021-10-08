package dtls

import (
	"bytes"
	"context"
	"crypto/sha256"

	"github.com/zjw1111/DTLShps/pkg/crypto/elliptic"
	"github.com/zjw1111/DTLShps/pkg/crypto/encryptedkey"
	"github.com/zjw1111/DTLShps/pkg/protocol"
	"github.com/zjw1111/DTLShps/pkg/protocol/alert"
	"github.com/zjw1111/DTLShps/pkg/protocol/extension"
	"github.com/zjw1111/DTLShps/pkg/protocol/handshake"
	"github.com/zjw1111/DTLShps/pkg/protocol/recordlayer"
)

func flight1Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert.Alert, error) {
	// HelloVerifyRequest can be skipped by the server,
	// so allow ServerHello during flight1 also
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence,
		handshakeCachePullRule{handshake.TypeHelloVerifyRequest, cfg.initialEpoch, false, true},
		handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, true},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok := msgs[handshake.TypeServerHello]; ok {
		// Flight1 and flight2 were skipped.
		// Parse as flight3.
		return flight3Parse(ctx, c, state, cache, cfg)
	}

	if h, ok := msgs[handshake.TypeHelloVerifyRequest].(*handshake.MessageHelloVerifyRequest); ok {
		// DTLS 1.2 clients must not assume that the server will use the protocol version
		// specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
		if !h.Version.Equal(protocol.Version1_0) && !h.Version.Equal(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
		}
		state.cookie = append([]byte{}, h.Cookie...)
		state.handshakeRecvSequence = seq
		return flight3, nil, nil
	}

	return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
}

func flight1Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert.Alert, error) {
	var zeroEpoch uint16
	state.localEpoch.Store(zeroEpoch)
	state.remoteEpoch.Store(zeroEpoch)
	state.namedCurve = defaultNamedCurve
	state.cookie = nil

	if err := state.localRandom.Populate(); err != nil {
		return nil, nil, err
	}

	extensions := []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.localSignatureSchemes,
		},
		&extension.RenegotiationInfo{
			RenegotiatedConnection: 0,
		},
	}
	if cfg.localPSKCallback == nil {
		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384},
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.localSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles: cfg.localSRTPProtectionProfiles,
		})
	}

	if cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}

	if len(cfg.serverName) > 0 {
		extensions = append(extensions, &extension.ServerName{ServerName: cfg.serverName})
	}

	var pkts []*packet

	pkts = append(pkts, &packet{
		record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Message: &handshake.MessageClientHello{
					Version:            protocol.Version1_2,
					Cookie:             state.cookie,
					Random:             state.localRandom,
					CipherSuiteIDs:     cipherSuiteIDs(cfg.localCipherSuites),
					CompressionMethods: defaultCompressionMethods(),
					Extensions:         extensions,
				},
			},
		},
	})

	if cfg.TestWithoutController && cfg.SkipHelloVerify {
		// send DTLShps packets without controller
		if psk, err := cfg.localPSKCallback(cfg.localPSKIdentityHint); err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		} else {
			nonce := state.localRandom.MarshalFixed()
			var buffer bytes.Buffer
			buffer.Write(psk)
			buffer.Write(nonce[:])
			psk_nonce := buffer.Bytes()
			hashkey := sha256.Sum256(psk_nonce)

			pkts = append(pkts, &packet{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &handshake.Handshake{
						Message: &handshake.MessageEncryptedKey{
							EncryptedKey: encryptedkey.AESCBCEncryptFromBytes(hashkey[:], []byte("this is encryptedkey for DTLShps")),
						},
					},
				},
			})
		}
	}

	return pkts, nil, nil
}
