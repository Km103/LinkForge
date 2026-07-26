# LinkForge

LinkForge is an open-source encrypted multipath tunnel that combines Ethernet,
Wi-Fi, USB tethering, and other independent internet connections. The client
stripes IP packets over authenticated UDP paths; a public relay reorders them,
forwards them to the internet, and bonds return traffic across the same paths.

This is an independent implementation. It is not affiliated with, based on,
or wire-compatible with Speedify.

> Status: production-oriented alpha. The data plane, managed one-click app,
> logging, telemetry, Linux relay, and Linux/Windows builds work. Commission an
> independent protocol and security audit before protecting sensitive traffic.

## Does Wi-Fi X + tethering Y equal X + Y?

That is the target. If Wi-Fi sustains X Mbps and tethering sustains Y Mbps,
LinkForge can approach X+Y minus encryption/UDP overhead and any relay,
destination, packet-loss, carrier, or latency bottleneck. Both access links
must be genuinely independent, and the relay must have at least X+Y capacity.
One short TCP transfer may be more sensitive to latency differences; parallel
downloads and multi-flow traffic usually approach the sum more easily.

```text
                         encrypted UDP path: Wi-Fi ─────────┐
 Applications → TUN → sequence + weighted scheduler         ├→ relay → NAT → internet
                         encrypted UDP path: USB tether ─────┘
                                      bounded reorder at both ends
```

A public relay is required because ordinary internet servers cannot reassemble
one connection arriving from multiple public source addresses.

## Managed one-click client

The primary user experience uses a LinkForge-operated relay. Each device gets:

- one platform binary;
- one short-lived, one-use activation code;
- the official `wintun.dll` on Windows.

The installer exchanges the activation code over HTTPS and creates a unique
mode-0600 `profile.json` locally. The profile contains no Wi-Fi, Ethernet, USB,
gateway, or route values. LinkForge discovers current physical default-route
interfaces, performs a short encrypted capacity calibration, protects the
relay path on each interface, and installs the tunnel routes when the user
clicks **Aggregate traffic**.

Linux installation:

```bash
sudo LINKFORGE_ACTIVATION_CODE=lf_... \
  ./deploy/linux/install-client-app.sh \
  --binary ./linkforge-linux-amd64 \
  --enrollment-url https://ENROLLMENT_HOST
```

Open **LinkForge** from the application menu (or browse to
<http://127.0.0.1:9090/>), then click **Aggregate traffic**.

Windows installation from an Administrator PowerShell:

```powershell
.\deploy\windows\install-client-app.ps1 `
  -SourceBinary .\linkforge-windows-amd64.exe `
  -EnrollmentUrl https://ENROLLMENT_HOST `
  -ActivationCode lf_... `
  -WintunDll .\wintun.dll
```

Double-click the installed LinkForge desktop shortcut and click
**Aggregate traffic**. See [Managed service and enrollment](docs/managed-service.md)
and [Windows client](docs/windows.md).

Treat the generated `profile.json` like a password. It is unique per device
and must never be committed to source control.

## Self-hosted relay

Self-hosting is the advanced option. Build the same open-source relay, deploy
it to a Linux VM with a public IPv4 address, provision a unique device ID/key
and tunnel IP, and give the client a profile pointing at that relay. Client UI
and auto-discovery are identical; only the enrollment profile changes.

See [Linux relay deployment](docs/deploy-linux.md). The repository contains
placeholders and configurable defaults only—no production relay address,
cloud account, SSH key, device credential, local interface, or gateway is
compiled into the product.

## Data-plane and operations features

- Linux and Windows clients; Linux is the reference relay platform.
- Automatic discovery of active physical IPv4 default-route interfaces.
- Short per-path encrypted calibration and cached relative capacity weights.
- Smooth weighted scheduling with RTT-aware health removal and reconnection.
- Global sequencing and bounded reordering for asymmetric path latency.
- AES-256-GCM per path, HMAC-SHA256 handshake, HKDF-SHA256 keys, fixed
  tunnel-IP anti-spoofing, anti-replay windows, and authenticated NAT rebinding.
- Source-specific relay route protection before full-tunnel `/1` routes.
- Live start/stop dashboard, compact throughput/path metrics, JSON status,
  Prometheus exposition, health/readiness probes, and structured logs.
- Unprivileged `doctor` load test that exercises every discovered path.
- In-memory encrypted two-path integration test, race checks, vet, and
  Linux/Windows cross-builds.

## Operator quick start

Prerequisites are Go 1.25+, root/CAP_NET_ADMIN on Linux, or Administrator on
Windows. `doctor` does not create a TUN and normally needs no elevation.

```bash
make build
./bin/linkforge keygen
cp examples/server.json server.json
cp examples/managed-profile.json profile.json
```

Put the generated device ID, unique key, relay address, and assigned tunnel IP
into the server credential and client profile. Then:

```bash
./bin/linkforge interfaces
./bin/linkforge doctor -config profile.json -duration 10s
sudo ./bin/linkforge app -profile profile.json
```

The low-level `client` command remains available for explicit path, weight, and
split-route configurations.

## Documentation

- [Managed service and enrollment](docs/managed-service.md)
- [Managed enrollment API](docs/enrollment-api.md)
- [How it works](docs/how-it-works.md)
- [Configuration reference](docs/configuration.md)
- [Linux relay deployment](docs/deploy-linux.md)
- [Windows client guide](docs/windows.md)
- [Operations and verification](docs/operations.md)
- [Wire protocol](docs/protocol.md)
- [Security policy](SECURITY.md)

## Current limitations

- Tunneled traffic is IPv4. Physical UDP support is currently IPv4-oriented.
- The open-source repository supplies enrollment, per-device records, and
  live revocation for one relay, not billing, account login, or relay HA.
- Forward-error correction, redundant-packet mode, kill-switch policy, and
  automatic relay-region selection are not implemented.
- Capacity calibration is intentionally short; unusual links may benefit from
  operator-supplied weights through the low-level client configuration.
- The protocol uses conservative standard primitives but has not received an
  independent audit.

## Development

```bash
make test
make race
make vet
make cross
```

Contributions are welcome under the [MIT License](LICENSE). Do not use
commercial product names or artwork in LinkForge branding.
