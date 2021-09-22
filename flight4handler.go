package dtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/zjw1111/DTLShps/pkg/crypto/clientcertificate"
	"github.com/zjw1111/DTLShps/pkg/crypto/elliptic"
	"github.com/zjw1111/DTLShps/pkg/crypto/encryptedkey"
	"github.com/zjw1111/DTLShps/pkg/crypto/prf"
	"github.com/zjw1111/DTLShps/pkg/crypto/signaturehash"
	"github.com/zjw1111/DTLShps/pkg/protocol"
	"github.com/zjw1111/DTLShps/pkg/protocol/alert"
	"github.com/zjw1111/DTLShps/pkg/protocol/extension"
	"github.com/zjw1111/DTLShps/pkg/protocol/handshake"
	"github.com/zjw1111/DTLShps/pkg/protocol/recordlayer"
)

func flight4Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert.Alert, error) { //nolint:gocognit
	var seq int
	var msgs map[handshake.Type]handshake.Message
	var ok bool
	if cfg.DTLShps {
		seq, msgs, ok = cache.fullPullMap(state.handshakeRecvSequence,
			// BUG?: If the Identity message is empty(optional), it means that the controller did not
			// send the Identity message, that is, the certificate verification failed
			handshakeCachePullRule{handshake.TypeIdentity, cfg.initialEpoch, true, false},
		)
	} else {
		seq, msgs, ok = cache.fullPullMap(state.handshakeRecvSequence,
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, true, true},
			handshakeCachePullRule{handshake.TypeClientKeyExchange, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeCertificateVerify, cfg.initialEpoch, true, true},
		)
	}
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if cfg.DTLShps {
		if h, hasIdentity := msgs[handshake.TypeIdentity].(*handshake.MessageIdentity); !hasIdentity {
			cfg.log.Error("Identity verify failed!")
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoIdentity}, errInvalidIdentity
		} else {
			cfg.log.Infof("Identity verify success! Identity is: %s\n", h.IdentityData)
		}
	}

	// Validate type
	var clientKeyExchange *handshake.MessageClientKeyExchange
	if clientKeyExchange, ok = msgs[handshake.TypeClientKeyExchange].(*handshake.MessageClientKeyExchange); !cfg.DTLShps && !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if h, hasCert := msgs[handshake.TypeCertificate].(*handshake.MessageCertificate); hasCert {
		state.PeerCertificates = h.Certificate
	}

	if h, hasCertVerify := msgs[handshake.TypeCertificateVerify].(*handshake.MessageCertificateVerify); hasCertVerify {
		if state.PeerCertificates == nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, errCertificateVerifyNoCertificate
		}

		// TODO Client Cert Verify
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeClientKeyExchange, cfg.initialEpoch, true, false},
		)

		// Verify that the pair of hash algorithm and signiture is listed.
		var validSignatureScheme bool
		for _, ss := range cfg.localSignatureSchemes {
			if ss.Hash == h.HashAlgorithm && ss.Signature == h.SignatureAlgorithm {
				validSignatureScheme = true
				break
			}
		}
		if !validSignatureScheme {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errNoAvailableSignatureSchemes
		}

		if err := verifyCertificateVerify(plainText, h.HashAlgorithm, h.Signature, state.PeerCertificates); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
		var chains [][]*x509.Certificate
		var err error
		var verified bool
		if cfg.clientAuth >= VerifyClientCertIfGiven {
			if chains, err = verifyClientCert(state.PeerCertificates, cfg.clientCAs); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
			verified = true
		}
		if cfg.verifyPeerCertificate != nil {
			if err := cfg.verifyPeerCertificate(state.PeerCertificates, chains); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
		}
		state.peerCertificatesVerified = verified
	}

	if !state.cipherSuite.IsInitialized() {
		serverRandom := state.localRandom.MarshalFixed()
		clientRandom := state.remoteRandom.MarshalFixed()

		var err error
		var preMasterSecret []byte
		if cfg.DTLShps {
			fmt.Println("server use DTLShps")
			fmt.Printf("state.preMasterSecret: %x\n", state.preMasterSecret)
			preMasterSecret = state.preMasterSecret
		} else if cfg.localPSKCallback != nil {
			var psk []byte
			if psk, err = cfg.localPSKCallback(clientKeyExchange.IdentityHint); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			state.IdentityHint = clientKeyExchange.IdentityHint
			preMasterSecret = prf.PSKPreMasterSecret(psk)
		} else {
			preMasterSecret, err = prf.PreMasterSecret(clientKeyExchange.PublicKey, state.localKeypair.PrivateKey, state.localKeypair.Curve)
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
			}
		}

		if state.extendedMasterSecret {
			var sessionHash []byte
			sessionHash, err = cache.sessionHash(state.cipherSuite.HashFunc(), cfg.initialEpoch)
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}

			state.masterSecret, err = prf.ExtendedMasterSecret(preMasterSecret, sessionHash, state.cipherSuite.HashFunc())
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			fmt.Printf("sessionHash: %x\n", sessionHash)
			fmt.Printf("masterSecret: %x\n", state.masterSecret)
		} else {
			state.masterSecret, err = prf.MasterSecret(preMasterSecret, clientRandom[:], serverRandom[:], state.cipherSuite.HashFunc())
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
		}

		if err := state.cipherSuite.Init(state.masterSecret, clientRandom[:], serverRandom[:], false); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)
	}

	// Now, encrypted packets can be handled
	if err := c.handleQueuedPackets(ctx); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	seq, msgs, ok = cache.fullPullMap(seq,
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}
	state.handshakeRecvSequence = seq

	if _, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeAnonymous {
		return flight6, nil, nil
	}

	// TODO clientAuth verify
	if !cfg.DTLShps {
		switch cfg.clientAuth {
		case RequireAnyClientCert:
			if state.PeerCertificates == nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, errClientCertificateRequired
			}
		case VerifyClientCertIfGiven:
			if state.PeerCertificates != nil && !state.peerCertificatesVerified {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, errClientCertificateNotVerified
			}
		case RequireAndVerifyClientCert:
			if state.PeerCertificates == nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, errClientCertificateRequired
			}
			if !state.peerCertificatesVerified {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, errClientCertificateNotVerified
			}
		case NoClientCert, RequestClientCert:
			return flight6, nil, nil
		}
	}

	return flight6, nil, nil
}

func flight4Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert.Alert, error) {
	extensions := []extension.Extension{&extension.RenegotiationInfo{
		RenegotiatedConnection: 0,
	}}
	if (cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret) && state.extendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}
	if state.srtpProtectionProfile != 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles: []SRTPProtectionProfile{state.srtpProtectionProfile},
		})
	}
	// TODO
	if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate {
		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384},
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	var pkts []*packet
	cipherSuiteID := uint16(state.cipherSuite.ID())

	pkts = append(pkts, &packet{
		record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Message: &handshake.MessageServerHello{
					Version:           protocol.Version1_2,
					Random:            state.localRandom,
					CipherSuiteID:     &cipherSuiteID,
					CompressionMethod: defaultCompressionMethods()[0],
					Extensions:        extensions,
				},
			},
		},
	})

	switch {
	case cfg.DTLShps:
		if !cfg.TestWithoutController {
			// send DTLShps packets with controller
			certificate, err := cfg.getCertificate(cfg.serverName)
			if err != nil {
				return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
			}

			pkts = append(pkts, &packet{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &handshake.Handshake{
						Message: &handshake.MessageCertificate{
							Certificate: certificate.Certificate,
						},
					},
				},
			})
		}

		if cfg.clientAuth > NoClientCert {
			pkts = append(pkts, &packet{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &handshake.Handshake{
						Message: &handshake.MessageCertificateRequest{
							CertificateTypes:        []clientcertificate.Type{clientcertificate.RSASign, clientcertificate.ECDSASign},
							SignatureHashAlgorithms: cfg.localSignatureSchemes,
						},
					},
				},
			})
		}

		if cfg.TestWithoutController {
			// send DTLShps packets without controller
			pkts = append(pkts, &packet{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &handshake.Handshake{
						Message: &handshake.MessageIdentity{
							IdentityData: []byte("This is DTLShps Server!"),
						},
					},
				},
			})

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

	case state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate:
		certificate, err := cfg.getCertificate(cfg.serverName)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
		}

		pkts = append(pkts, &packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageCertificate{
						Certificate: certificate.Certificate,
					},
				},
			},
		})

		serverRandom := state.localRandom.MarshalFixed()
		clientRandom := state.remoteRandom.MarshalFixed()

		// Find compatible signature scheme
		signatureHashAlgo, err := signaturehash.SelectSignatureScheme(cfg.localSignatureSchemes, certificate.PrivateKey)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
		}

		signature, err := generateKeySignature(clientRandom[:], serverRandom[:], state.localKeypair.PublicKey, state.namedCurve, certificate.PrivateKey, signatureHashAlgo.Hash)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		state.localKeySignature = signature

		pkts = append(pkts, &packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageServerKeyExchange{
						EllipticCurveType:  elliptic.CurveTypeNamedCurve,
						NamedCurve:         state.namedCurve,
						PublicKey:          state.localKeypair.PublicKey,
						HashAlgorithm:      signatureHashAlgo.Hash,
						SignatureAlgorithm: signatureHashAlgo.Signature,
						Signature:          state.localKeySignature,
					},
				},
			},
		})

		if cfg.clientAuth > NoClientCert {
			pkts = append(pkts, &packet{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &handshake.Handshake{
						Message: &handshake.MessageCertificateRequest{
							CertificateTypes:        []clientcertificate.Type{clientcertificate.RSASign, clientcertificate.ECDSASign},
							SignatureHashAlgorithms: cfg.localSignatureSchemes,
						},
					},
				},
			})
		}
	case cfg.localPSKIdentityHint != nil:
		// To help the client in selecting which identity to use, the server
		// can provide a "PSK identity hint" in the ServerKeyExchange message.
		// If no hint is provided, the ServerKeyExchange message is omitted.
		//
		// https://tools.ietf.org/html/rfc4279#section-2
		pkts = append(pkts, &packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageServerKeyExchange{
						IdentityHint: cfg.localPSKIdentityHint,
					},
				},
			},
		})
	case state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeAnonymous:
		pkts = append(pkts, &packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageServerKeyExchange{
						EllipticCurveType: elliptic.CurveTypeNamedCurve,
						NamedCurve:        state.namedCurve,
						PublicKey:         state.localKeypair.PublicKey,
					},
				},
			},
		})
	}

	pkts = append(pkts, &packet{
		record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Message: &handshake.MessageServerHelloDone{},
			},
		},
	})

	return pkts, nil, nil
}
