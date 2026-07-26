//go:build linux

package netbind

import (
	"errors"
	"syscall"
)

func bindToInterface(name string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		controlErr := raw.Control(func(fd uintptr) {
			socketErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
		})
		if controlErr != nil {
			return controlErr
		}
		// Diagnostics remain usable without elevation. The local source address
		// still selects a path; production clients run with CAP_NET_RAW/ADMIN.
		if errors.Is(socketErr, syscall.EPERM) || errors.Is(socketErr, syscall.EACCES) {
			return nil
		}
		return socketErr
	}
}
