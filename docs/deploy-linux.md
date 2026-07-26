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
sudo install -m 0640 examples/server.json /etc/linkforge/server.json
sudo install -m 0755 deploy/linux/linkforge-firewall /usr/local/libexec/linkforge-firewall
sudo install -m 0644 deploy/linux/linkforge-firewall.service /etc/systemd/system/
sudo install -m 0644 deploy/linux/linkforge-server.service /etc/systemd/system/
```

Create `/etc/linkforge/linkforge.env` owned by root. Environment-backed keys
are preferable for manually managed relays:

```text
LINKFORGE_CLIENT_KEY=replace-with-keygen-output
```

```bash
sudo chmod 0600 /etc/linkforge/linkforge.env
```

Edit `server.json`: set a unique client ID, key reference, and unused tunnel IP
for every device. Never share one credential between devices.

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

Allow inbound UDP/4430 to the relay. Do not expose dashboard TCP/9091 publicly.
Use an SSH tunnel:

```bash
ssh -L 9091:127.0.0.1:9091 ubuntu@RELAY_HOST
```

Then browse to <http://127.0.0.1:9091/>.

Cloud security groups are separate from the guest firewall. Confirm both the
cloud rule and the local UDP listener.

## Start and verify

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now linkforge-server.service
sudo systemctl status linkforge-firewall.service linkforge-server.service
curl --fail http://127.0.0.1:9091/readyz
sudo ss -lunp | grep ':4430'
```

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
