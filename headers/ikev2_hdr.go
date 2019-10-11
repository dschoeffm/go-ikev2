package headers

import (
	"encoding/binary"
	"fmt"
	"log"
)

// --------------- IKE Hdr 3.1 --------------- //

// Ikev2Hdr This struct holds information about the IKEv2 header
type Ikev2Hdr struct {
	InitSa       uint64
	RespSa       uint64
	NextPayload  byte
	Version      byte
	ExchangeType byte
	Flags        byte
	MessageID    uint32
	Length       uint32
}

// NewIKEv2Hdr This function constructs an IKEv2 header
func NewIKEv2Hdr(content []byte) *Ikev2Hdr {
	if len(content) != 28 {
		log.Panic("Length of IKEv2 header needs to be 28")
	}
	var hdr Ikev2Hdr

	hdr.InitSa = binary.BigEndian.Uint64(content[0:8])
	hdr.RespSa = binary.BigEndian.Uint64(content[8:16])
	hdr.NextPayload = content[16]
	hdr.Version = content[17]
	hdr.ExchangeType = content[18]
	hdr.Flags = content[19]
	hdr.MessageID = binary.BigEndian.Uint32(content[20:24])
	hdr.Length = binary.BigEndian.Uint32(content[24:28])

	return &hdr
}

// PayloadsLength This returns the length of everything after the header
func (hdr *Ikev2Hdr) PayloadsLength() uint32 {
	return hdr.Length - uint32(28)
}

// GetDesc Get a textual description of the header
func (hdr *Ikev2Hdr) GetDesc() string {
	ret := fmt.Sprintf(`SPI Init:       0x%x
SPI Resp:       0x%x
Next Payload:   0x%x
Version:        0x%x
Exchange Type:  0x%x
Flags:          0x%x
Message ID:     0x%x
Length:         0x%x
`, hdr.InitSa, hdr.RespSa, hdr.NextPayload, hdr.Version,
		hdr.ExchangeType, hdr.Flags, hdr.MessageID, hdr.Length)
	print(ret)
	return ret
}
