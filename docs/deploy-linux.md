# Deploy a Linux relay

Ubuntu 24.04+ is the reference relay. An Azure/AWS/GCP VM needs a public IPv4
address or mapped UDP endpoint, inbound UDP/4430, outbound internet access, and
enough CPU/egress capacity for all bonded clients.

## Build and install

```bash
sudo apt-get update
sudo apt-get install -y iptables
make build
sudo install -m 0755 bin/linkforge /usr/local/bin/linkforge
sudo install -d -m 0750 /etc/linkforge
sudo install -m 0640 examples/server-managed.json /etc/linkforge/server.json
sudo install -m 0755 deploy/linux/linkforge-firewall /usr/local/libexec/linkforge-firewall
sudo install -m 0644 deploy/linux/linkforge-firewall.service /etc/systemd/system/
sudo install -m 0644 deploy/linux/linkforge-server.service /etc/systemd/system/
```

For a managed relay, replace `RELAY_HOST` in `server.json` with the public DNS
name and keep the UDP port. Create `/etc/linkforge/linkforge.env` owned by root
with two independently generated control-plane secrets:

```text
LINKFORGE_ADMIN_TOKEN=<at-least-32-random-characters>
LINKFORGE_CONTROL_MASTER_KEY=<base64-encoded-32-byte-key>
```

```bash
sudo sh -c 'umask 077
admin=$(openssl rand -base64 48 | tr -d "\n")
master=$(openssl rand -base64 32 | tr -d "\n")
printf "LINKFORGE_ADMIN_TOKEN=%s\nLINKFORGE_CONTROL_MASTER_KEY=%s\n" \
  "$admin" "$master" > /etc/linkforge/linkforge.env'
sudo chmod 0600 /etc/linkforge/linkforge.env
```

The service creates `/var/lib/linkforge/control.db` with mode `0600`. Device
keys are encrypted in that database. Back up the database and master key
separately; losing the master key makes stored device keys unrecoverable.

For a manually managed/self-hosted relay, use `examples/server.json` instead,
put an environment-backed key in the env file, and configure a unique client
ID, key, and unused tunnel IP for every device. Never share one credential
between devices. Static and managed credentials can coexist during migration.

## Forwarding and NAT

The idempotent firewall helper:

- auto-detects the first IPv4 default-route interface unless configured;
- inserts scoped forward/return rules into `DOCKER-USER` when Docker owns the
  host firewall, otherwise at the start of `FORWARD`;
- adds source NAT only for the LinkForge tunnel CIDR;
- removes only its exact rules when the unit stops.

Set explicit values when auto-detection or defaults do not match the VM:

```text
# /etc/linkforge/firewall.env
LINKFORGE_PUBLIC_INTERFACE=PUBLIC_INTERFACE
LINKFORGE_TUN_INTERFACE=LINKFORGE_TUN_INTERFACE
LINKFORGE_TUNNEL_CIDR=LINKFORGE_TUNNEL_CIDR
```

Replace all placeholders. If the server uses the example defaults, only the
public interface may need setting. Then:

```bash
sudo install -m 0644 deploy/linux/99-linkforge-forward.conf /etc/sysctl.d/
sudo sysctl --system
sudo systemctl daemon-reload
sudo systemctl enable --now linkforge-firewall.service
sudo iptables -S DOCKER-USER 2>/dev/null || sudo iptables -S FORWARD
sudo iptables -t nat -S POSTROUTING
```

Do not flush an existing production ruleset. If another firewall manager
rewrites `FORWARD`/`DOCKER-USER` after boot, order the LinkForge firewall unit
after that manager or express the same three narrow rules in the manager.

## Cloud firewall

Allow inbound UDP/4430 to the relay. Managed enrollment additionally needs
TCP/80 and TCP/443 for certificate issuance and HTTPS. Do not expose dashboard
TCP/9091 or management TCP/8443 publicly. Use an SSH tunnel for either private
operator interface:

```bash
ssh -L 9091:127.0.0.1:9091 ubuntu@RELAY_HOST
```

Then browse to <http://127.0.0.1:9091/>.

Cloud security groups are separate from the guest firewall. Confirm both the
cloud rule and the local UDP listener.

## HTTPS enrollment

The LinkForge management service deliberately binds to `127.0.0.1:8443`.
Install Caddy, replace `ENROLLMENT_HOST` in `deploy/linux/Caddyfile` with the
relay's public DNS name, and install that file as Caddy's configuration:

```bash
sudo install -m 0644 deploy/linux/Caddyfile /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
```

Caddy obtains and renews the public certificate. The supplied configuration
proxies only `/v1/enroll` and `/v1/healthz`; public requests to `/v1/admin/*`
return 404. Keep administrative calls on loopback through SSH.

## Start and verify

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now linkforge-server.service
sudo systemctl status linkforge-firewall.service linkforge-server.service
curl --fail http://127.0.0.1:9091/readyz
curl --fail http://127.0.0.1:8443/v1/healthz
sudo ss -lunp | grep ':4430'
```

Create a one-use activation code from an SSH session, then give only the code,
enrollment URL, binary, and installer to the user:

```bash
set -a
. /etc/linkforge/linkforge.env
set +a
curl --fail-with-body \
  -H "Authorization: Bearer $LINKFORGE_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"USER_ID","device_name":"laptop","expires_in":"15m"}' \
  http://127.0.0.1:8443/v1/admin/activations
unset LINKFORGE_ADMIN_TOKEN LINKFORGE_CONTROL_MASTER_KEY
```

See [enrollment-api.md](enrollment-api.md) for device listing, key rotation,
revocation, and endpoint details.

From a remote client, run `doctor`. Then start full aggregation and verify the
client's public IPv4 equals the relay's egress address. Inspect relay TUN and
NAT counters:

```bash
ip -s link show linkforge0
sudo iptables -t nat -L POSTROUTING -n -v
journalctl -u linkforge-server -f -o cat
```

The project deliberately stores no VM address, cloud identifier, SSH-key path,
or live client credential in tracked source.
