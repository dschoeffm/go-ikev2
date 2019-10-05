package headers

type message struct {
	assembled []byte
}

type payload struct {
	payloadType    byte
	payloadContent []byte
}

func newMessage(content []byte) *message {
	return &message{assembled: content}
}

func (msg *message) IKEv2Hdr() *ikev2Hdr {
	return NewIKEv2Hdr(msg.assembled)
}

func (msg *message) Payloads() []payload {
	payloadsRaw := msg.assembled[28:]
	payloadsLength := len(payloadsRaw)
	payloadStart := 0
	payloads := make([]payload, 1)

	nextPayload := msg.IKEv2Hdr().NextPayload()

	for (payloadStart < payloadsLength) && (nextPayload != 0) {
		pl_generic := newIKEv2PayloadHdr(payloadsRaw[payloadStart:])
		payloads = append(payloads, payload{payloadType: nextPayload,
			payloadContent: pl_generic.Payload()})
		payloadStart += int(pl_generic.Length())
		nextPayload = pl_generic.NextPayload()
	}

	return payloads
}
