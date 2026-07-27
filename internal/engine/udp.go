package engine

import (
	"log/slog"
	"net"
)

// A larger socket queue absorbs short bursts from bonded paths while the
// receiver authenticates, reorders, and writes packets to the TUN device.
// The kernel may cap this value; SetReadBuffer/SetWriteBuffer remain portable
// across the Windows and Linux implementations supported by net.UDPConn.
const udpSocketBufferSize = 4 << 20

func tuneUDPSocket(conn *net.UDPConn, logger *slog.Logger) {
	if err := conn.SetReadBuffer(udpSocketBufferSize); err != nil {
		logger.Warn("could not enlarge UDP receive buffer", "requested_bytes", udpSocketBufferSize, "error", err)
	}
	if err := conn.SetWriteBuffer(udpSocketBufferSize); err != nil {
		logger.Warn("could not enlarge UDP send buffer", "requested_bytes", udpSocketBufferSize, "error", err)
	}
}
