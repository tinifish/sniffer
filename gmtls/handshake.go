package gmtls

import "golang.org/x/crypto/cryptobyte"

type HandshakeRecord struct {
	Type        uint8            `json:"type"`
	ClientHello *ClientHelloInfo `json:"client_hello,omitempty"`
}

func UnmarshalHandshake(handshake []byte) *HandshakeRecord {
	hs := &HandshakeRecord{Type: handshake[0]}
	str := cryptobyte.String(handshake[4:])
	switch hs.Type {
	case 1: //client_hello
		hs.ClientHello = UnmarshalClientHello(str)
	case 2: //server_hello
	case 4:
	//new_session_ticket(4),
	case 5: //end_of_early_data(5),
	case 8: //encrypted_extensions(8),
	case 11: //certificate
	case 12: //server_key_exchange
	case 13: //certificate_request
	case 14: //server_hello_done
	case 15: //certificate_verify
	case 16: //client_key_exchange
	case 20: //finished
	case 24: //key_update(24),
	case 254: //message_hash(254),
	case 255:
	}
	return hs
}
