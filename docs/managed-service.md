# Managed service and device enrollment

LinkForge is managed-first and self-hostable:

1. The normal user receives a device bundle for a LinkForge-operated relay.
2. The advanced user may deploy the same relay code on their own Linux VM and
   issue an activation code that points to it.

There is no behavioral switch in the client. The packaged binary is the same;
enrollment creates a local `profile.json` that selects the relay and
authenticates exactly one device.

## What a client needs

| Platform | Required files | One-time action |
|---|---|---|
| Linux amd64 | `linkforge-linux-amd64`, activation code, enrollment URL, Linux installer assets | Run the installer as root. |
| Windows amd64 | `linkforge-windows-amd64.exe`, activation code, enrollment URL, official signed `wintun.dll`, PowerShell installer | Run the installer as Administrator. |

After installation, the privileged background process owns TUN and route
changes. The user opens the local dashboard and clicks **Aggregate traffic**.
They do not enter interface names, source IPs, gateways, weights, routes, or a
relay address.

The installer sends the one-time activation code over HTTPS, receives a
unique device identity/key/address, and writes the profile with restricted
permissions. Users never import or hand-edit a profile.

The dashboard is bound to loopback. Its start/stop POST requests require a
random in-memory capability token embedded in the same-origin page. Prometheus
and status endpoints are read-only.

## What the profile contains

A managed profile contains:

- relay DNS name or address and UDP port;
- a unique device ID;
- a unique 256-bit device key;
- the device's assigned tunnel IPv4 address;
- configurable tunnel timing, MTU, logging, and metrics defaults.

It intentionally contains no machine-specific physical interface data.
Protect it like a password: mode `0600` on Linux and SYSTEM/Administrators-only
ACLs on Windows. Revoke a lost device by deleting or rotating only that
credential on the relay.

## Click behavior

On **Aggregate traffic**, the app:

1. discovers active non-virtual IPv4 interfaces that own a default route;
2. opens one relay socket bound to each physical source/interface;
3. runs a two-second encrypted echo calibration per path;
4. derives relative scheduler weights and caches them while interfaces remain
   unchanged;
5. installs a source-specific physical route guard for the relay;
6. opens/configures the TUN and installs two IPv4 `/1` routes;
7. starts encrypted packet striping, bounded reordering, health checks, logs,
   and metrics.

On **Stop aggregation** or process shutdown, it waits for the engine to close,
then removes the TUN, `/1` routes, and source-specific policy tables. The
route guard is established before the full-tunnel routes, so the tunnel does
not recursively encapsulate its own relay traffic.

## Configuration versus hardcoding

LinkForge has configurable product defaults, not deployment constants:

| Value | Default | Why |
|---|---:|---|
| Relay UDP port | `4430` in examples | A conventional single listener; profile-configurable. |
| Client dashboard | `127.0.0.1:9090` | Loopback-only local control; CLI/installer-configurable. |
| Relay dashboard | `127.0.0.1:9091` | Keeps unauthenticated telemetry private by default. |
| Tunnel MTU | `1280` | Conservative across tethered networks; profile-configurable. |
| Health interval | `2s` | Fast failover without excessive keepalive traffic. |
| Reorder delay/window | `80ms` / `512` | Bounds latency and memory; profile-configurable. |
| Example tunnel subnet | `10.77.0.0/24` | Documentation/default only; server and firewall-configurable. |

The following are always supplied at deployment or enrollment time and are
never compiled into source: production relay host, cloud subscription,
resource group, SSH key, public egress interface, device ID/key/tunnel IP, and
client Ethernet/Wi-Fi/USB addresses.

## Managed relay operator boundary

The included single-relay control plane issues expiring one-use activation
codes, creates unique encrypted per-device credentials, persists non-secret
device records, and applies rotation/revocation live. Its admin API is
loopback-only; TLS exposes only health and enrollment.

A public multi-region offering still needs account login, billing, usage
policy, relay selection, capacity admission, upgrades, abuse response, a
replicated database, and HA. See [enrollment-api.md](enrollment-api.md).

## Self-hosting

Follow [deploy-linux.md](deploy-linux.md), create a unique key/ID with
`linkforge keygen`, assign an unused tunnel IP inside the relay subnet, and
place matching values in the relay allow-list and device profile. Use a DNS
name where possible so a VM replacement does not require a client reinstall.
