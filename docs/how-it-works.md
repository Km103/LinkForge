# How LinkForge works

## Why a relay is necessary

Ethernet, Wi-Fi, and tethering normally have different local and public IP
addresses. If half of a TCP connection suddenly appears at a website from a
second public IP, that website treats it as a different or invalid connection.
LinkForge therefore creates one virtual IP interface (TUN) and sends its
packets to a relay. The internet sees only the relay's public IP.

## Packet lifecycle

Before packet forwarding, the managed app discovers active physical
default-route interfaces, runs a short encrypted echo calibration, and assigns
relative weights from returned bytes. It first protects the relay route through
each physical source/interface, then creates the TUN and full-tunnel routes.

### Uplink

1. The operating system routes an application packet into the LinkForge TUN.
2. The client rejects packets whose source is not its assigned tunnel IP.
3. A global sequence number is prepended to the complete IP packet.
4. Smooth weighted round-robin chooses a healthy physical path. A small RTT
   penalty prevents a very slow path from dominating without turning it into
   failover-only.
5. The packet is encrypted with that path's AES-256-GCM key. The authenticated
   header identifies the client session, path, and per-path nonce sequence.
6. The UDP socket is bound to the path's local address (for example the Wi-Fi
   address or USB-tether address).
7. The relay authenticates and decrypts it. Packets arriving early wait in a
   bounded reorder buffer.
8. Ordered IP packets enter the relay TUN. Linux forwarding and NAT send them
   to the internet.

### Downlink

1. A reply reaches the relay's public interface and NAT restores its destination
   to the client's tunnel IP.
2. The relay TUN reads it and finds the client session by destination IP.
3. The relay assigns a global downlink sequence and selects a healthy client
   path.
4. The client authenticates, decrypts, and reorders packets from all paths.
5. Ordered packets enter the client TUN and the original application receives
   them.

## How X+Y is achieved

For weights 3:1, the smooth scheduler sends roughly three packets over Wi-Fi
for each packet over USB. A 90 Mbps Wi-Fi path and 30 Mbps tether should
normally use 3 and 1. The app derives this ratio automatically; the low-level
client also permits operator-supplied weights.

The theoretical sum is not a guarantee. Usable throughput is bounded by:

- the relay's CPU, NIC, and public bandwidth;
- the destination server and its path to the relay;
- the capacity and packet loss of each local connection;
- UDP/IP/AEAD overhead;
- TCP congestion behavior, particularly when RTTs differ significantly.

The default 80 ms reorder deadline masks common Wi-Fi/cellular delay
differences. If one packet is still missing, later packets are released so a
lost UDP datagram never deadlocks the tunnel. Increase `reorder_delay` when
combining a very low-latency wired link with a high-latency cellular link.

## Path health and failover

The client sends an encrypted timestamp ping every two seconds. Authenticated
traffic or pongs refresh path health and its EWMA RTT. After four missed health
intervals, the scheduler stops assigning packets to that path and attempts a
fresh authenticated handshake. If the relay restarted, the client rebuilds
the complete session. The dashboard and logs show removal and recovery.

## Session and key model

Every client has a random 128-bit ID, an independent 256-bit pre-shared key,
and a fixed tunnel IP declared on the relay. Each path handshake has fresh
client/server nonces and derives a unique path key with HKDF-SHA256. Encryption
nonces combine direction, path ID, and a monotonic per-path sequence.

Each running client process also generates a shared 128-bit instance nonce.
All of that process's physical paths join one relay session. A later process
using the same enrolled device ID has a different instance nonce, so the relay
immediately retires the stale session and resets both global data sequences.
The last authenticated CLOSE also removes the session immediately. This avoids
carrying reorder state across diagnostics, crashes, upgrades, or repeated
Aggregate/Stop cycles.

The cleartext routing header is authenticated as AEAD additional data.
Per-direction replay windows accept ordinary UDP reordering but reject
duplicates. The relay updates a NAT-rebound remote address only after a packet
authenticates.

See [protocol.md](protocol.md) for the byte-level format and [SECURITY.md](../SECURITY.md)
for the threat model.
