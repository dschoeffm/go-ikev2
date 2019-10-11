package networking

// Packet This represents a packet received from a peer, or to be send to a peer
type Packet struct {
	// TODO
	// local/remote IP/Port
	content []byte
}

// GetContent Retuns the content of the packet
func (p *Packet) GetContent() []byte {
	return p.content
}

// Provider This interface models some kind of network interface
type Provider interface {
	GetRecvChannel() <-chan Packet
	GetSendChannel() chan<- Packet
}
