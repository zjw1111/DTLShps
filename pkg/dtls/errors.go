package dtls

import "errors"

var (
	errNotEnoughRoomForNonce     = errors.New("dtls: Buffer not long enough to contain nonce")
	errBufferTooSmall            = errors.New("dtls: buffer is too small")
	errCertificateUnset          = errors.New("dtls: handshakeMessageCertificate can not be marshalled without a certificate")
	errCipherSuiteNoIntersection = errors.New("dtls: Client+Server do not support any shared cipher suites")
	errCipherSuiteUnset          = errors.New("dtls: server hello can not be created without a cipher suite")
	errCompressionmethodUnset    = errors.New("dtls: server hello can not be created without a compression method")
	errCookieTooLong             = errors.New("dtls: cookie must not be longer then 255 bytes")
	errCookieMismatch            = errors.New("dtls: Client+Server cookie does not match")
	errDTLSPacketInvalidLength   = errors.New("dtls: packet is too short")
	errHandshakeMessageUnset     = errors.New("dtls: handshake message unset, unable to marshal")
	errInvalidCipherSpec         = errors.New("dtls: cipher spec invalid")
	errInvalidCipherSuite        = errors.New("dtls: invalid or unknown cipher suite")
	errInvalidCompressionMethod  = errors.New("dtls: invalid or unknown compression method")
	errInvalidContentType        = errors.New("dtls: invalid content type")
	errInvalidEllipticCurveType  = errors.New("dtls: invalid or unknown elliptic curve type")
	errInvalidExtensionType      = errors.New("dtls: invalid extension type")
	errInvalidHandshakeType      = errors.New("dtls: invalid handshake type")
	errInvalidHashAlgorithm      = errors.New("dtls: invalid hash algorithm")
	errInvalidNamedCurve         = errors.New("dtls: invalid named curve")
	errInvalidSignatureAlgorithm = errors.New("dtls: invalid signature algorithm")
	errLengthMismatch            = errors.New("dtls: data length and declared length do not match")
	errNotImplemented            = errors.New("dtls: feature has not been implemented yet")
	errSequenceNumberOverflow    = errors.New("dtls: sequence number overflow")
	errServerMustHaveCertificate = errors.New("dtls: Certificate is mandatory for server")
	errUnableToMarshalFragmented = errors.New("dtls: unable to marshal fragmented handshakes")
)
