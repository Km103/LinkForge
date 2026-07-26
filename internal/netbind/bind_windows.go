//go:build windows

package netbind

import (
	"math/bits"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

const ipUnicastIF = 31

func bindToInterface(name string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		var socketErr error
		controlErr := raw.Control(func(fd uintptr) {
			// Winsock expects the interface index in network byte order.
			index := int(bits.ReverseBytes32(uint32(iface.Index)))
			socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIF, index)
		})
		if controlErr != nil {
			return controlErr
		}
		return socketErr
	}
}
