package headers

import (
	"encoding/binary"
	"fmt"
)

// --------------- Generic Payload Hdr 3.2 --------------- //

type ikev2PayloadHdr struct {
	assembled []byte // should be 4 byte long
}

func newIKEv2PayloadHdr(content []byte) *ikev2PayloadHdr {
	return &ikev2PayloadHdr{assembled: content}
}

func (hdr *ikev2PayloadHdr) NextPayload() byte {
	return hdr.assembled[0]
}

func (hdr *ikev2PayloadHdr) Reserved() byte {
	return hdr.assembled[1]
}

func (hdr *ikev2PayloadHdr) Length() uint16 {
	// TODO: Validation: length must be at least 4 (hdr)
	return binary.BigEndian.Uint16(hdr.assembled[2:4])
}

func (hdr *ikev2PayloadHdr) LengthNoHdr() uint16 {
	return hdr.Length() - 4
}

func (hdr *ikev2PayloadHdr) Payload() []byte {
	// TODO This may fail, if the content is bogus and not 4 byte long...
	return hdr.assembled[4:]
}

func (hdr *ikev2PayloadHdr) GetGenericDesc() string {
	ret := fmt.Sprintf(`Generic Payload Header:
  Next Payload:     0x%x
  Reserved:         0x%x
  Payload Length:   0x%x
`, hdr.NextPayload(), hdr.Reserved(), hdr.Length())
	return ret
}
