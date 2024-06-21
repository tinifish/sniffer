package gmtls

type Record struct {
	ContentType      TLSType
	Version          TLSVersion
	Length           uint16
	ChangeCipherSpec *ChangeCipherSpecRecord
	Handshake        *HandshakeRecord
	AppData          *AppDataRecord
	Alert            *AlertRecord
}

type ChangeCipherSpecRecord struct {
}

type AppDataRecord struct {
}

type AlertRecord struct {
}

// TLSType defines the type of data after the TLS Record
type TLSType uint8

// TLSType known values.
const (
	TLSChangeCipherSpec TLSType = 20
	TLSAlert            TLSType = 21
	TLSHandshake        TLSType = 22
	TLSApplicationData  TLSType = 23
	TLSUnknown          TLSType = 255
)

// String shows the register type nicely formatted
func (tt TLSType) String() string {
	switch tt {
	default:
		return "Unknown"
	case TLSChangeCipherSpec:
		return "Change Cipher Spec"
	case TLSAlert:
		return "Alert"
	case TLSHandshake:
		return "Handshake"
	case TLSApplicationData:
		return "Application Data"
	}
}

// TLSVersion represents the TLS version in numeric format
type TLSVersion uint16

// Strings shows the TLS version nicely formatted
func (tv TLSVersion) String() string {
	switch tv {
	default:
		return "Unknown"
	case 0x0200:
		return "SSL 2.0"
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
}
