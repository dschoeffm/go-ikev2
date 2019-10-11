package crypto

type DhGrp interface {
	SomeFun() []byte
}

type Prf interface {
	SomeFun() []byte
}

type Encr interface {
	SomeFun() []byte
	IsAEAD() bool
}

type Auth interface {
	SomeFun() []byte
}
