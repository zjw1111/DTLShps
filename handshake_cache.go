package dtls

import (
	"sync"

	"github.com/zjw1111/DTLShps/pkg/crypto/prf"
	"github.com/zjw1111/DTLShps/pkg/protocol/handshake"
)

type handshakeCacheItem struct {
	typ             handshake.Type
	isClient        bool
	epoch           uint16
	messageSequence uint16
	data            []byte
}

type handshakeCachePullRule struct {
	typ      handshake.Type
	epoch    uint16
	isClient bool
	optional bool
}

type handshakeCache struct {
	cache []*handshakeCacheItem
	mu    sync.Mutex
}

func newHandshakeCache() *handshakeCache {
	return &handshakeCache{}
}

func (h *handshakeCache) push(data []byte, epoch, messageSequence uint16, typ handshake.Type, isClient bool) bool { //nolint
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, i := range h.cache {
		if i.messageSequence == messageSequence &&
			i.isClient == isClient {
			return false
		}
	}

	h.cache = append(h.cache, &handshakeCacheItem{
		data:            append([]byte{}, data...),
		epoch:           epoch,
		messageSequence: messageSequence,
		typ:             typ,
		isClient:        isClient,
	})
	return true
}

// returns a list handshakes that match the requested rules
// the list will contain null entries for rules that can't be satisfied
// multiple entries may match a rule, but only the last match is returned (ie ClientHello with cookies)
func (h *handshakeCache) pull(isDTLShps bool, rules ...handshakeCachePullRule) []*handshakeCacheItem {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]*handshakeCacheItem, len(rules))
	for i, r := range rules {
		for _, c := range h.cache {
			// In DTLShps, controller may add or remove packets in handshake, so the messageSequence
			// maybe different from client and server. But, when calculate hash value, we need client
			// and server have the same data, include the same messageSequence.
			// 
			// Now, we change ALL messageSequence to 0x0000. Attention: Because variable `c` is the
			// pointer of handshakeCacheItem, this will change the messageSequence in handshakeCache.
			// This will not affect the final handshake process, because when we calculate the hash
			// value, we no longer need the real messageSequence of the packets.
			//
			// FIXME: We can add an option in the flight processing method to identify at which packet
			// the messageSequence should be increased or decreased, making the messageSequence in the
			// client and server consistent.
			if isDTLShps {
				c.data[4] = 0x00
				c.data[5] = 0x00
			}
			if c.typ == r.typ && c.isClient == r.isClient && c.epoch == r.epoch {
				switch {
				case out[i] == nil:
					out[i] = c
				case out[i].messageSequence < c.messageSequence:
					out[i] = c
				}
			}
		}
	}

	return out
}

// fullPullMap pulls all handshakes between rules[0] to rules[len(rules)-1] as map.
func (h *handshakeCache) fullPullMap(startSeq int, rules ...handshakeCachePullRule) (int, map[handshake.Type]handshake.Message, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ci := make(map[handshake.Type]*handshakeCacheItem)
	for _, r := range rules {
		var item *handshakeCacheItem
		for _, c := range h.cache {
			if c.typ == r.typ && c.isClient == r.isClient && c.epoch == r.epoch {
				switch {
				case item == nil:
					item = c
				case item.messageSequence < c.messageSequence:
					item = c
				}
			}
		}
		if !r.optional && item == nil {
			// Missing mandatory message.
			return startSeq, nil, false
		}
		ci[r.typ] = item
	}
	out := make(map[handshake.Type]handshake.Message)
	seq := startSeq
	for _, r := range rules {
		t := r.typ
		i := ci[t]
		if i == nil {
			continue
		}
		rawHandshake := &handshake.Handshake{}
		if err := rawHandshake.Unmarshal(i.data); err != nil {
			return startSeq, nil, false
		}
		if uint16(seq) != rawHandshake.Header.MessageSequence {
			// There is a gap. Some messages are not arrived.
			return startSeq, nil, false
		}
		seq++
		out[t] = rawHandshake.Message
	}
	return seq, out, true
}

// pullAndMerge calls pull and then merges the results, ignoring any null entries
func (h *handshakeCache) pullAndMerge(isDTLShps bool, rules ...handshakeCachePullRule) []byte {
	merged := []byte{}

	for _, p := range h.pull(isDTLShps, rules...) {
		if p != nil {
			merged = append(merged, p.data...)
		}
	}
	return merged
}

// sessionHash returns the session hash for Extended Master Secret support
// https://tools.ietf.org/html/draft-ietf-tls-session-hash-06#section-4
func (h *handshakeCache) sessionHash(isDTLShps bool, hf prf.HashFunc, epoch uint16, additional ...[]byte) ([]byte, error) {
	merged := []byte{}

	// Order defined by https://tools.ietf.org/html/rfc5246#section-7.3
	// NOTE: extendedMasterSecret hash calc
	var handshakeBuffer []*handshakeCacheItem
	if isDTLShps {
		handshakeBuffer = h.pull(isDTLShps,
			handshakeCachePullRule{handshake.TypeServerHello, epoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificateRequest, epoch, false, false},
			handshakeCachePullRule{handshake.TypeServerHelloDone, epoch, false, false},
		)
	} else {
		handshakeBuffer = h.pull(isDTLShps,
			handshakeCachePullRule{handshake.TypeClientHello, epoch, true, false},
			handshakeCachePullRule{handshake.TypeServerHello, epoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, epoch, false, false},
			handshakeCachePullRule{handshake.TypeServerKeyExchange, epoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificateRequest, epoch, false, false},
			handshakeCachePullRule{handshake.TypeServerHelloDone, epoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, epoch, true, false},
			handshakeCachePullRule{handshake.TypeClientKeyExchange, epoch, true, false},
		)
	}

	for _, p := range handshakeBuffer {
		if p == nil {
			continue
		}

		merged = append(merged, p.data...)
	}
	if !isDTLShps {
		for _, a := range additional {
			merged = append(merged, a...)
		}
	}

	hash := hf()
	if _, err := hash.Write(merged); err != nil {
		return []byte{}, err
	}

	return hash.Sum(nil), nil
}
