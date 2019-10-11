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
	t := &transform{assembled: content}
	// TODO make sure slice is long enough
	if len(t.assembled) != int(t.Length()) {
		t.assembled = t.assembled[:int(t.Length())]
	}

	return t
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

type Proposal struct {
	assembled []byte
}

func newProposal(content []byte) *Proposal {
	return &Proposal{assembled: content}
}

func (hdr *Proposal) LastSubstruc() bool {
	return hdr.assembled[0] == 0
}

func (hdr *Proposal) Reserved() uint8 {
	return uint8(hdr.assembled[1])
}

func (hdr *Proposal) Length() uint16 {
	return binary.BigEndian.Uint16(hdr.assembled[2:4])
}

func (hdr *Proposal) Num() uint8 {
	return uint8(hdr.assembled[4])
}

func (hdr *Proposal) ProtocolID() uint8 {
	return uint8(hdr.assembled[5])
}

func (hdr *Proposal) SpiSize() uint8 {
	return uint8(hdr.assembled[6])
}

func (hdr *Proposal) NumTransforms() uint8 {
	return uint8(hdr.assembled[7])
}

func (hdr *Proposal) Spi() []byte {
	return hdr.assembled[8:(8 + hdr.SpiSize())]
}

func (hdr *Proposal) Transforms() []transform {
	// TODO: What if not transform is sent at all? (Not allowed by RFC, but
	// anyways...)
	transformsRaw := hdr.assembled[(8 + hdr.SpiSize()):]
	transforms := make([]transform, 0)
	moreTransforms := true
	transStart := 0
	allLength := len(transformsRaw)

	// Don't rely only on moreTransforms. Could be bogus...
	for moreTransforms && (transStart < allLength) {
		trans := newTransform(transformsRaw[transStart:])
		moreTransforms = !trans.LastSubstruc()
		transStart += int(trans.Length())
		transforms = append(transforms, *trans)
	}

	return transforms
}

func (hdr *Proposal) GetDesc() string {

	ret := fmt.Sprintf(`Proposal:
	Last Substruc: 0x%t
	Reserved:      0x%x
	Length:        0x%x
	Num:           0x%x
	ProtocolId:    0x%x
	SpiSize:       0x%x
	NumTransforms: 0x%x
	SPI:           0x%x
  `, hdr.LastSubstruc(), hdr.Reserved(), hdr.Length(),
		hdr.Num(), hdr.ProtocolID(), hdr.SpiSize(),
		hdr.NumTransforms(), hdr.Spi())

	for _, trans := range hdr.Transforms() {
		ret += trans.GetDesc()
	}
	return ret
}

// --- Complete Hdr ---

// Ikev2Sa Struct to describe one IKEv2 Sa payload
type Ikev2Sa struct {
	assembled []byte
}

// NewIKEv2Sa Create a new IKEv2 SA payload from a generic payload
func NewIKEv2Sa(content []byte) *Ikev2Sa {
	var ret Ikev2Sa
	ret.assembled = content
	return &ret
}

// GetType Returns static byte as defined in the RFC
func (Ikev2Sa) GetType() byte {
	return 33
}

// Proposals Get all the proposals from the IKEv2 SA payload
func (hdr *Ikev2Sa) Proposals() []Proposal {
	proposalsRaw := hdr.assembled
	proposalsRawLen := len(proposalsRaw)
	moreProposals := true
	propStart := 0
	proposals := make([]Proposal, 0)

	// TODO this somehow needs to be save from loops
	for moreProposals && (propStart < proposalsRawLen) {
		proposal := newProposal(proposalsRaw[propStart:])
		moreProposals = !proposal.LastSubstruc()
		proposals = append(proposals, *proposal)
		propStart += int(proposal.Length())
	}

	return proposals
}

// GetDesc Returns a string describing the IKEv2 SA payload
func (hdr *Ikev2Sa) GetDesc() string {
	ret := ""
	for _, prop := range hdr.Proposals() {
		ret += prop.GetDesc()
	}
	return ret
}
