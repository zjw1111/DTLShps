package handshake

// MessageIdentity is a DTLShps Handshake Message.
// This message is the identity information of the
// client/server obtained from the certificate.
type MessageIdentity struct {
	IdentityData []byte
}

// Type returns the Handshake Type
func (m MessageIdentity) Type() Type {
	return TypeIdentity
}

// Marshal encodes the Handshake
func (m *MessageIdentity) Marshal() ([]byte, error) {
	return append([]byte{}, m.IdentityData...), nil
}

// Unmarshal populates the message from encoded data
func (m *MessageIdentity) Unmarshal(data []byte) error {
	m.IdentityData = append([]byte{}, data...)
	return nil
}
