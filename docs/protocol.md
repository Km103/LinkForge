# LinkForge Multipath Protocol v1

The protocol is independent and intentionally small. Multi-byte integers use
network byte order.

## Datagram header

Every UDP datagram starts with 28 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII magic `LFMP` |
| 4 | 1 | version = 1 |
| 5 | 1 | type: HELLO, WELCOME, DATA, PING, PONG, PROBE, PROBE_REPLY, CLOSE |
| 6 | 2 | flags, currently zero |
| 8 | 8 | session ID |
| 16 | 4 | path ID; bit 31 is reserved for nonce direction |
| 20 | 8 | per-path, per-direction sequence |

HELLO and WELCOME payloads are plaintext but HMAC-SHA256 authenticated.
All later payloads are AES-256-GCM ciphertext with the entire header as
additional authenticated data.

## Handshake

The current HELLO v2 payload contains:

| Size | Field |
|---:|---|
| 16 | enrolled client ID |
| 16 | client-process instance nonce, shared by all its paths |
| 16 | fresh path nonce |
| 8 | Unix timestamp |
| 2 | fixed-point scheduler weight (configured weight × 100) |
| 1 | path-name length |
| variable | path name, at most 63 bytes |
| 32 | HMAC-SHA256 using the `linkforge/hello/v2` domain |

The relay looks up the client ID, checks the HMAC and ±2 minute clock window,
then reuses an existing response for a retransmitted path nonce. Paths with
the same authenticated instance nonce join one session. A different instance
nonce for the same client ID atomically replaces the stale session and resets
global sequence/reorder state. This distinguishes a new client process from a
second physical path without storing machine-specific state in the profile.

Relays accept the legacy HELLO v1 layout during rolling upgrades. It omitted
the instance nonce and used the `linkforge/hello/v1` HMAC domain. New clients
always emit HELLO v2.

WELCOME contains the echoed client nonce, fresh 128-bit server nonce, timestamp,
and HMAC over its domain separator, header, and fields. Its header assigns the
random 64-bit session ID and 31-bit path ID.

The path key is 32 bytes from HKDF-SHA256:

```text
IKM  = client pre-shared key
salt = client_nonce || server_nonce
info = "linkforge/path-key/v1" || session_id || path_id
```

## Encrypted nonce

The 96-bit GCM nonce is `directional_path_id || sequence`. The server-to-client
direction sets bit 31 of the path ID. Path IDs never use that bit, making nonce
spaces disjoint even though one key serves both directions.

## DATA payload

After decryption:

| Size | Field |
|---:|---|
| 8 | global sequence for this session and direction |
| remaining | one complete IPv4 packet |

The GCM sequence protects nonce uniqueness and replay per path. The global
sequence restores order across paths.

## Replay and resource limits

- A 64-packet sliding replay window exists per path and direction.
- Handshakes older/newer than two minutes are rejected.
- Path names are at most 63 bytes.
- The TUN MTU limits normal data; diagnostics cap payloads at 1200 bytes.
- Reordering is bounded by both time and packet count.

## Compatibility policy

Unknown datagram-header versions fail closed. The HELLO v2 extension is
unambiguously length-checked and independently authenticated, allowing a relay
to accept HELLO v1 during migration. Future incompatible header or encrypted
packet changes will increment the datagram version. New packet types or
negotiated flags may be added without reusing existing meanings.
