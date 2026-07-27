# Operations and verification

## Safe rollout

1. Start the relay and confirm `/readyz` returns HTTP 200.
2. Run `linkforge interfaces` on the client with all sources connected.
3. Add explicit client paths and run `doctor` without elevation.
4. Confirm every expected path is healthy and has non-zero sent/received bytes.
5. For an advanced/manual rollout, start with no routes and then a split
   prefix.
6. For the managed app, click Aggregate traffic and verify the automatically
   installed relay guard and `/1` routes.

## Proving bonding

```bash
linkforge doctor -config client.json -duration 10s | tee doctor.json
```

`connectivity_verified` proves at least one path authenticated and echoed
encrypted traffic. `bonding_verified` requires at least two exercised paths,
and `all_paths_verified` requires every expected path. Compare the aggregate Mbps with
single-path runs where the other paths have `"enabled": false`.

The reported `recommended_weight` values are ratios based on returned echo
traffic. Treat them as a starting point, repeat the test, and prefer stable
real-world throughput measurements over a single short UDP run.

During real traffic, verify:

- dashboard “healthy paths” equals the expected count;
- both per-path byte counters continually increase;
- combined throughput exceeds the fastest single-path baseline;
- `linkforge_no_path_drops_total`, authentication failures, and TUN errors
  remain zero;
- reorder skips are low. Sustained skips mean loss or too-small
  `reorder_delay`.

## Logs

JSON logs are designed for journald, Loki, Elasticsearch, or any structured
collector. Important events include:

- `path authenticated`: local address, relay, session/path IDs, and weight;
- `multipath session established`: number of usable paths;
- `path unhealthy` / `path recovered`: failover evidence;
- `path statistics`: per-path RTT, bytes, and write errors;
- `tunnel statistics` / `relay statistics`: aggregate counters;
- `reorder deadline skipped missing packets` at debug level: individual gap;
- `tunnel statistics` / `relay statistics`: cumulative `reorder_skips` count;
- `spoofed tunnel packet dropped`: assigned-IP violation.

Example journal query:

```bash
journalctl -u linkforge-server -f -o cat
```

Do not log pre-shared keys. Config parsing and engine logs never emit them.

## HTTP telemetry

| Endpoint | Purpose |
|---|---|
| `/` or `/dashboard` | Offline-capable live control deck |
| `/api/v1/status` | Machine-readable snapshot |
| `/metrics` | Prometheus exposition |
| `/healthz` | Process is alive |
| `/readyz` | TUN and UDP service are ready |

The HTTP listener has no authentication. Bind it to loopback, a private
management network, or place it behind an authenticated TLS reverse proxy.

## Alert suggestions

- readyz != 200 for 60 seconds;
- `linkforge_path_healthy == 0` for an expected path;
- rate of no-path drops > 0;
- authentication failures increase unexpectedly;
- TUN errors > 0;
- reorder skips exceed 0.1% of received packets;
- relay CPU > 80% or UDP receive errors/drops increase.

## Full-tunnel routing

The managed app preserves relay reachability outside the TUN before installing
`0.0.0.0/1` and `128.0.0.0/1`. On Linux it creates a policy table and
source-address rule for every physical path; on Windows it creates one relay
host route per interface. A single relay `/32` route through one gateway would
collapse all paths onto that interface.

The following is illustrative of the Linux policy created automatically:

```bash
ip rule add from 192.168.1.20/32 table 101 priority 101
ip route add RELAY_IP/32 via 192.168.1.1 dev wlan0 table 101
ip route add default via 192.168.1.1 dev wlan0 table 101

ip rule add from 192.168.42.10/32 table 102 priority 102
ip route add RELAY_IP/32 via 192.168.42.129 dev usb0 table 102
ip route add default via 192.168.42.129 dev usb0 table 102
```

The actual table IDs, sources, gateways, interfaces, and resolved relay
addresses are discovered at runtime. They are removed on Stop aggregation.
Do not copy these illustrative values into a managed profile.

## Incident response

If traffic stalls, first remove the LinkForge routes (or stop the client and
restore the original route), then check:

1. Relay UDP firewall and `readyz`.
2. Client local addresses still exist.
3. `doctor` per-path results.
4. Authentication failure counters and clock synchronization.
5. Relay forwarding/NAT counters: `sudo nft list table ip linkforge`.
6. MTU symptoms. Reduce TUN MTU from 1280 only after capturing evidence.
