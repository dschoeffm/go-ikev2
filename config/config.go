package config

import "ikev2/crypto"

// Proposal This struct contains all the information about crypto proposals
type Proposal struct {
	Prfs   []crypto.Prf   `yaml:"prfs"`
	DhGrps []crypto.DhGrp `yaml:"dhGrps"`
	Encrs  []crypto.Encr  `yaml:"encrs"`
	Auths  []crypto.Auth  `yaml:"auths"`
}

// ChildSa This struct contains information about child SAs
type ChildSa struct {
	SaType           string     `yaml:"saType"` // Only esp for now
	Proposals        []Proposal `yaml:"proposals"`
	RemoteTrafficSel string     `yaml:"remoteTrafficSel"` // CIDR
	// add actions later
}

// PeerConfig Configuration for connections to peers
type PeerConfig struct {
	Name         string     `yaml:"name"`
	RemoteAddr   string     `yaml:"remoteAddr"`
	IkeProposals []Proposal `yaml:"ikeProposals"`
	ChildSas     []ChildSa  `yaml:"childSas"`

	// DPD stuff
	// SA lifetimes
}

// Provider Interface to get configuration data
type Provider interface {
	GetPeerConfig() *PeerConfig
}
