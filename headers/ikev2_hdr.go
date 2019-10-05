package headers

import (
	"encoding/binary"
	"fmt"
)

// --------------- IKE Hdr 3.1 --------------- //

type ikev2Hdr struct {
	assembled []byte // should be 28 byte long
}

func NewIKEv2Hdr(content []byte) *ikev2Hdr {
	return &ikev2Hdr{assembled: content}
}

func (hdr *ikev2Hdr) InitSa() uint64 {
	return binary.BigEndian.Uint64(hdr.assembled[0:8])
}

func (hdr *ikev2Hdr) RespSa() uint64 {
	return binary.BigEndian.Uint64(hdr.assembled[8:16])
}

func (hdr *ikev2Hdr) NextPayload() byte {
	return hdr.assembled[16]
}

func (hdr *ikev2Hdr) Version() byte {
	return hdr.assembled[17]
}

func (hdr *ikev2Hdr) ExchangeType() byte {
	return hdr.assembled[18]
}

func (hdr *ikev2Hdr) Flags() byte {
	return hdr.assembled[19]
}

func (hdr *ikev2Hdr) MessageId() uint32 {
	return binary.BigEndian.Uint32(hdr.assembled[20:24])
}

func (hdr *ikev2Hdr) Length() uint32 {
	return binary.BigEndian.Uint32(hdr.assembled[24:28])
}

func (hdr *ikev2Hdr) PayloadsLength() uint32 {
	return hdr.Length() - uint32(28)
}

func (hdr *ikev2Hdr) Validate() bool {
	if len(hdr.assembled) == 28 {
		return true
	} else {
		return false
	}
}

func (hdr *ikev2Hdr) GetDesc() string {
	ret := fmt.Sprintf(`SPI Init:       0x%x
SPI Resp:       0x%x
Next Payload:   0x%x
Version:        0x%x
Exchange Type:  0x%x
Flags:          0x%x
Message ID:     0x%x
Length:         0x%x
`, hdr.InitSa(), hdr.RespSa(), hdr.NextPayload(), hdr.Version(),
		hdr.ExchangeType(), hdr.Flags(), hdr.MessageId(), hdr.Length())
	return ret
}
