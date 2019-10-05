package headers

import (
	"encoding/binary"
	"fmt"
)

// --------------- Security Association Payload 3.3 --------------- //

// --- Transform Attributes ---

type transformAttribute struct {
	assembled []byte
}

func newTransformAttribute(content []byte) *transformAttribute {
	return &transformAttribute{assembled: content}
}

func (hdr *transformAttribute) Format() bool {
	/* https://tools.ietf.org/html/rfc7296 3.3.5
	   Attribute Format (AF) (1 bit) - Indicates whether the data
	   attribute follows the Type/Length/Value (TLV) format or a
	   shortened Type/Value (TV) format.  If the AF bit is zero (0), then
	   the attribute uses TLV format; if the AF bit is one (1), the TV
	   format (with two-byte value) is used.
	*/
	raw := binary.BigEndian.Uint16(hdr.assembled[0:2])
	return (raw & 0x8000) != 0
}

func (hdr *transformAttribute) IsTv() bool {
	return hdr.Format()
}

func (hdr *transformAttribute) IsTlv() bool {
	return !hdr.Format()
}

func (hdr *transformAttribute) Type() uint16 {
	raw := binary.BigEndian.Uint16(hdr.assembled[0:2])
	return raw & 0x7fff
}

func (hdr *transformAttribute) ValueLength() uint16 {
	// TODO: This should probably check if the slice is even long enough for
	// the TLV (if it is a TLV)
	if hdr.IsTv() {
		return 0
	} else {
		return binary.BigEndian.Uint16(hdr.assembled[2:4])
	}
}

func (hdr *transformAttribute) TotalLength() uint16 {
	return hdr.ValueLength() + 4
}

// --- Transforms ---

type transform struct {
	assembled []byte
}

func newTransform(content []byte) *transform {
	return &transform{assembled: content}
}

func (hdr *transform) LastSubstruc() bool {
	return hdr.assembled[0] == 0
}

func (hdr *transform) Reserved1() uint8 {
	return uint8(hdr.assembled[1])
}

func (hdr *transform) Length() uint16 {
	return binary.BigEndian.Uint16(hdr.assembled[2:4])
}

func (hdr *transform) Type() uint8 {
	return uint8(hdr.assembled[4])
}

func (hdr *transform) Reserved2() uint8 {
	return uint8(hdr.assembled[5])
}

func (hdr *transform) TransformId() uint16 {
	return binary.BigEndian.Uint16(hdr.assembled[6:8])
}

func (hdr *transform) TransformAttributes() []transformAttribute {
	// TODO: What if the length of a TLV is bogus (way to long) and we read
	// outside of slice bounds?
	attributes := make([]transformAttribute, 1)
	attr_start := uint16(0)
	attr_all_length := hdr.Length() - 8
	attributes_raw := hdr.assembled[8:hdr.Length()]

	for attr_start < attr_all_length {
		attr := newTransformAttribute(attributes_raw[attr_start:])
		attributes = append(attributes, *attr)
		attr_start += attr.TotalLength()
	}

	return attributes
}

func (hdr *transform) GetDesc() string {
	ret := fmt.Sprintf(`Transform:
  Last Substruc:    0x%t
  Reserved1:        0x%x
  Transform Length: 0x%x
  Transform Type:   0x%x
  Reserved2:        0x%x
  TransformId:      0x%x
`, hdr.LastSubstruc(), hdr.Reserved1(), hdr.Length(),
		hdr.Type(), hdr.Reserved2(), hdr.TransformId())
	return ret
}

// --- Proposals ---

type proposal struct {
	assembled []byte
}

func newProposal(content []byte) *proposal {
	return &proposal{assembled: content}
}

func (hdr *proposal) LastSubstruc() bool {
	return hdr.assembled[0] == 0
}

func (hdr *proposal) Reserved() uint8 {
	return uint8(hdr.assembled[1])
}

func (hdr *proposal) Length() uint16 {
	return binary.BigEndian.Uint16(hdr.assembled[2:4])
}

func (hdr *proposal) Num() uint8 {
	return uint8(hdr.assembled[4])
}

func (hdr *proposal) ProtocolId() uint8 {
	return uint8(hdr.assembled[5])
}

func (hdr *proposal) SpiSize() uint8 {
	return uint8(hdr.assembled[6])
}

func (hdr *proposal) NumTransforms() uint8 {
	return uint8(hdr.assembled[7])
}

func (hdr *proposal) Spi() []byte {
	return hdr.assembled[8:(8 + hdr.SpiSize())]
}

func (hdr *proposal) Transforms() []transform {
	// TODO: What if not transform is sent at all? (Not allowed by RFC, but
	// anyways...)
	transforms_raw := hdr.assembled[8:(8 + hdr.SpiSize())]
	transforms := make([]transform, 1)
	moreTransforms := true
	trans_start := 0
	all_length := len(transforms_raw)

	// Don't rely only on moreTransforms. Could be bogus...
	for moreTransforms && (trans_start < all_length) {
		trans := newTransform(transforms_raw[trans_start:])
		moreTransforms = !trans.LastSubstruc()
		trans_start += int(trans.Length())
		transforms = append(transforms, *trans)
	}

	return transforms
}

// func GetDesc...

// --- Complete Hdr ---

// TODO make use of generic payload hdr

type ikev2Sa struct {
	ikev2PayloadHdr
}

func NewIKEv2Sa(content []byte) *ikev2Sa {
	var ret ikev2Sa
	ret.assembled = content
	return &ret
}

func (hdr *ikev2Sa) Proposals() []proposal {
	proposalsRaw := hdr.Payload()
	proposalsRawLen := len(proposalsRaw)
	moreProposals := true
	propStart := 0
	proposals := make([]proposal, 1)

	for moreProposals && (propStart < proposalsRawLen) {
		proposal := newProposal(proposalsRaw[propStart:])
		moreProposals = !proposal.LastSubstruc()
		proposals = append(proposals, *proposal)
	}

	return proposals
}

func (hdr *ikev2Sa) GetDesc() string {
	return ""
}
