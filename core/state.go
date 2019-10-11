package core

const saTypeIke = 0
const saTypeEsp = 1
const saTypeAh = 2

type saEsp struct {
	spi      uint32
	encr     int
	encrKey  []byte
	integ    int
	integKey []byte
	dhGrp    int
	esn      bool
}

// Nobody uses AH anyways...

type saIke struct {
	spi      uint64
	encr     int
	encrKey  []byte
	prf      int
	integ    int
	integKey []byte
	dhGrp    int
}

const stateSaInit = 1
const stateSaAuth = 2
const stateSaEstablished = 3

// State This struct defines the state of an IPsec connection
type State struct {
	State  int
	IkeSas []saIke
	EspSas []saEsp
}
