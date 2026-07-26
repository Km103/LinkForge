#!/bin/sh
set -eu

binary=""
profile=""

usage() {
    echo "usage: sudo $0 --binary PATH --profile PATH" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary)
            [ "$#" -ge 2 ] || usage
            binary="$2"
            shift 2
            ;;
        --profile)
            [ "$#" -ge 2 ] || usage
            profile="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

[ "$(id -u)" -eq 0 ] || {
    echo "run this installer as root" >&2
    exit 1
}
[ -f "$binary" ] || {
    echo "LinkForge binary not found: $binary" >&2
    exit 1
}
[ -f "$profile" ] || {
    echo "LinkForge profile not found: $profile" >&2
    exit 1
}
[ -c /dev/net/tun ] || {
    echo "/dev/net/tun is unavailable" >&2
    exit 1
}

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
install -o root -g root -m 0755 "$binary" /usr/local/bin/linkforge
install -d -o root -g root -m 0750 /etc/linkforge
install -o root -g root -m 0600 "$profile" /etc/linkforge/profile.json
install -o root -g root -m 0644 "$script_dir/linkforge-client-app.service" \
    /etc/systemd/system/linkforge-client-app.service
install -o root -g root -m 0644 "$script_dir/linkforge.desktop" \
    /usr/share/applications/linkforge.desktop

systemctl daemon-reload
systemctl enable --now linkforge-client-app.service
systemctl is-active --quiet linkforge-client-app.service

echo "LinkForge installed. Open LinkForge from the application menu,"
echo "or browse to http://127.0.0.1:9090/ and click Aggregate traffic."
