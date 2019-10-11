package headers

import (
	"log"
)

// Message Sescribes one packet received by the peer / sent to the peer
type Message struct {
	assembled []byte
}

// PayloadRaw Describes the raw payload without any further content information
type PayloadRaw struct {
	payloadType    byte
	payloadContent []byte
}

// This is an anti-pattern. It is only used, because only Payload functions
// will be used with this function (GetDesc())
func (p *PayloadRaw) getPayload() Payload {
	switch p.payloadType {
	case 33:
		log.Println("Found IKEv2 SA payload")
		return NewIKEv2Sa(p.payloadContent)
	default:
		return nil
	}
}

// Payload Interface to access the payloads of a message
type Payload interface {
	GetDesc() string
	GetType() byte
}

// NewMessage Construct a new Message from raw bytes
func NewMessage(content []byte) *Message {
	return &Message{assembled: content}
}

// IKEv2Hdr Every message has a IKEv2 hdr. Return this
func (msg *Message) IKEv2Hdr() *Ikev2Hdr {
	return NewIKEv2Hdr(msg.assembled[0:28])
}

// PayloadsRaw Get the raw payloads of this message
func (msg *Message) PayloadsRaw() []PayloadRaw {
	log.Println("PayloadsRaw called")
	payloadsRaw := msg.assembled[28:]
	payloadsLength := len(payloadsRaw)
	payloadStart := 0
	payloads := make([]PayloadRaw, 1)

	nextPayload := msg.IKEv2Hdr().NextPayload

	for (payloadStart < payloadsLength) && (nextPayload != 0) {
		log.Printf("Found Payload: %d", nextPayload)
		// TODO read length first - restrict slice
		plGeneric := newIKEv2PayloadHdr(payloadsRaw[payloadStart:])
		plGeneric.GetGenericDesc()
		payloads = append(payloads, PayloadRaw{payloadType: nextPayload,
			payloadContent: plGeneric.Payload()})
		payloadStart += int(plGeneric.Length())
		nextPayload = plGeneric.NextPayload()
	}

	return payloads
}

func (msg *Message) GetDesc() string {
	ret := ""
	for _, payloadRaw := range msg.PayloadsRaw() {
		pl := payloadRaw.getPayload()
		if pl != nil {
			ret += payloadRaw.getPayload().GetDesc()
		}
	}
	return ret
}
