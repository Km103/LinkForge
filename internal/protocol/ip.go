package protocol

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrUnsupportedIP = errors.New("unsupported or malformed IP packet")

func IPVersion(packet []byte) int {
	if len(packet) == 0 {
		return 0
	}
	return int(packet[0] >> 4)
}

func SourceIP(packet []byte) (netip.Addr, error) {
	switch IPVersion(packet) {
	case 4:
		if len(packet) < 20 || int(binary.BigEndian.Uint16(packet[2:4])) > len(packet) {
			return netip.Addr{}, ErrUnsupportedIP
		}
		var raw [4]byte
		copy(raw[:], packet[12:16])
		return netip.AddrFrom4(raw), nil
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, ErrUnsupportedIP
		}
		var raw [16]byte
		copy(raw[:], packet[8:24])
		return netip.AddrFrom16(raw), nil
	default:
		return netip.Addr{}, ErrUnsupportedIP
	}
}

func DestinationIP(packet []byte) (netip.Addr, error) {
	switch IPVersion(packet) {
	case 4:
		if len(packet) < 20 || int(binary.BigEndian.Uint16(packet[2:4])) > len(packet) {
			return netip.Addr{}, ErrUnsupportedIP
		}
		var raw [4]byte
		copy(raw[:], packet[16:20])
		return netip.AddrFrom4(raw), nil
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, ErrUnsupportedIP
		}
		var raw [16]byte
		copy(raw[:], packet[24:40])
		return netip.AddrFrom16(raw), nil
	default:
		return netip.Addr{}, ErrUnsupportedIP
	}
}
