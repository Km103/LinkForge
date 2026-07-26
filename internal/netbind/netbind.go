// Package netbind creates UDP sockets pinned to a physical interface. Binding
// both the source address and interface prevents a multipath socket from
// silently following another connection's default route.
package netbind

import (
	"context"
	"fmt"
	"net"
)

func DialUDP(ctx context.Context, local, remote *net.UDPAddr, interfaceName string) (*net.UDPConn, error) {
	dialer := net.Dialer{LocalAddr: local}
	if interfaceName != "" {
		dialer.Control = bindToInterface(interfaceName)
	}
	connection, err := dialer.DialContext(ctx, "udp", remote.String())
	if err != nil {
		return nil, err
	}
	udp, ok := connection.(*net.UDPConn)
	if !ok {
		_ = connection.Close()
		return nil, fmt.Errorf("dial returned %T instead of UDP", connection)
	}
	return udp, nil
}
