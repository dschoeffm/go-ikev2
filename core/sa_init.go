package core

import (
	"ikev2/headers"
	"ikev2/networking"
	"log"
)

/*
func PrintSaInit(message_bytes []byte) string {
	msg := headers.NewMessage(message_bytes)
	return msg.GetDesc()
}
*/

func clasifyAndAction(payload headers.PayloadRaw, state *State) {

}

// HandleSaInitMsg This function is concerned with processing an init messsage
func (state *State) HandleSaInitMsg(
	msg *headers.Message,
	pkt *networking.Packet,
	sendChannel <-chan networking.Packet) {
	log.Println("Handling incoming INIT msg")

	for _, payload := range msg.PayloadsRaw() {
		clasifyAndAction(payload, state)
	}
}
