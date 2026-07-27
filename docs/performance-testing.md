# Performance testing

`doctor` proves path authentication and provides short capacity hints. It is
not an end-to-end tunnel benchmark because it does not create a TUN, route real
TCP traffic, or exercise relay forwarding. Use the controlled procedure below
before making throughput claims.

## Fair comparison

Compare direct and tunneled traffic against the same relay VM, at nearly the
same time, for at least 15 seconds per direction. Test each physical interface
alone first, then test all interfaces together. A public speed-test site is a
useful user check but is not a controlled A/B baseline because its server and
path selection can change between runs.

The expected relationship is approximately:

```text
tunnel throughput <= sum of independent usable path capacities
```

It is not mathematically guaranteed to equal X+Y. UDP/IP/AEAD overhead, the
smaller tunnel MTU, loss, latency differences, the destination, and relay
capacity all reduce the usable total. Links sharing a radio, ISP uplink, or
carrier bottleneck are not independent. A successful bonding result exceeds
the fastest single-path tunnel run; it need not equal the sum of unrelated
speed-test readings.

## Safe split-tunnel test

Install `iperf3` on the relay and client. Bind the relay listener only to its
LinkForge tunnel address; this does not require exposing the benchmark port to
the internet:

```bash
iperf3 -s -1 -B "$LINKFORGE_RELAY_TUNNEL_IP"
```

Create a temporary client profile from the enrolled profile. Keep its existing
server, client ID, key, and assigned tunnel IP; change only the traffic policy:

```bash
umask 077
jq '.traffic_mode = "manual" | .routes = [] |
    .metrics.listen = "127.0.0.1:19090"' \
  /etc/linkforge/profile.json > /tmp/linkforge-benchmark.json
sudo linkforge client -config /tmp/linkforge-benchmark.json
```

Assigning the tunnel address installs only its connected private prefix. The
default route stays physical, so the test cannot take over normal internet
traffic. In another terminal, verify there are no full-tunnel `/1` routes,
then test downlink and uplink:

```bash
ip -4 route show
iperf3 -c "$LINKFORGE_RELAY_TUNNEL_IP" -R -t 15 -O 2
iperf3 -c "$LINKFORGE_RELAY_TUNNEL_IP"    -t 15 -O 2
```

Stop the client normally so it sends authenticated CLOSE and removes the TUN
route. Delete the temporary profile afterward.

## Evidence to capture

Before and after each run, record Linux UDP socket drops:

```bash
nstat -az UdpRcvbufErrors UdpSndbufErrors
```

Record these Prometheus metrics from both client and relay:

- `linkforge_sent_bytes_total` and `linkforge_received_bytes_total`;
- `linkforge_reorder_skips_total`;
- per-path bytes, health, RTT, replay drops, and write errors;
- TUN errors, authentication failures, and no-path drops.

Socket-drop deltas, replay drops, write errors, authentication failures, and
TUN errors should be zero. Some reorder skips can reflect real UDP loss, but a
sustained high ratio indicates a lossy path or unsuitable reorder delay. Use
bytes or packets over the exact test interval when calculating the ratio; the
exported counters are cumulative for the process lifetime.

For a controlled direct baseline, temporarily expose an `iperf3` TCP listener
only to the test client's current public `/32`, run the same two commands
against the relay public IP, and immediately remove that firewall rule. Never
leave a public benchmark listener or broad inbound rule running.
