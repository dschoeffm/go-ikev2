package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	//	"ikev2/headers"
	"log"
	"net"
)

func main() {
	//content := make([]byte, 28)
	//example_hdr := headers.NewIKEv2Hdr(content)
	//print(example_hdr.GetDesc())

	// listen to incoming udp packets
	pc, err := net.ListenPacket("udp", ":1053")
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	for {
		buf := make([]byte, 1024)
		log.Println("Waiting for packet")
		n, addr, err := pc.ReadFrom(buf)
		log.Println("Got packet")
		if err != nil {
			continue
		}
		go serve(pc, addr, buf[:n], privateKey)
	}

}

func serve(pc net.PacketConn, addr net.Addr, buf []byte, key *ecdsa.PrivateKey) {
	//example_hdr := headers.NewIKEv2Hdr(buf)

	//if example_hdr.Validate() {
	//	print(example_hdr.GetDesc())
	//}

	log.Println("Siging and verifying")
	hash := sha256.Sum256(buf)

	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: (0x%x, 0x%x)\n", r, s)

	valid := ecdsa.Verify(&key.PublicKey, hash[:], r, s)
	fmt.Println("signature verified:", valid)

	both := append(r.Bytes(), s.Bytes()...) // what are the ... for?
	fmt.Printf("%x", both)

	sEnc := b64.StdEncoding.EncodeToString(both)
	pc.WriteTo([]byte(sEnc), addr)
}
