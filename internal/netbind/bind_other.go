//go:build !linux && !windows

package netbind

import "syscall"

func bindToInterface(_ string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error { return nil }
}
