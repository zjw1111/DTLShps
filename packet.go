package dtls

import "github.com/zjw1111/DTLShps/pkg/protocol/recordlayer"

type packet struct {
	record                   *recordlayer.RecordLayer
	shouldEncrypt            bool
	resetLocalSequenceNumber bool
}
