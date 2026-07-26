#!/bin/sh
set -eu

binary=""
profile=""
enrollment_url=""

usage() {
    echo "usage:" >&2
    echo "  sudo $0 --binary PATH --profile PATH" >&2
    echo "  sudo LINKFORGE_ACTIVATION_CODE=lf_... $0 --binary PATH --enrollment-url HTTPS_URL" >&2
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
        --enrollment-url)
            [ "$#" -ge 2 ] || usage
            enrollment_url="$2"
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
if [ -n "$profile" ] && [ -n "$enrollment_url" ]; then
    echo "set either --profile or --enrollment-url, not both" >&2
    exit 1
fi
if [ -n "$profile" ]; then
    [ -f "$profile" ] || {
        echo "LinkForge profile not found: $profile" >&2
        exit 1
    }
elif [ -n "$enrollment_url" ]; then
    [ -n "${LINKFORGE_ACTIVATION_CODE:-}" ] || {
        echo "LINKFORGE_ACTIVATION_CODE is required for managed enrollment" >&2
        exit 1
    }
else
    usage
fi
[ -c /dev/net/tun ] || {
    echo "/dev/net/tun is unavailable" >&2
    exit 1
}

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
install -o root -g root -m 0755 "$binary" /usr/local/bin/linkforge
install -d -o root -g root -m 0750 /etc/linkforge
if [ -n "$profile" ]; then
    install -o root -g root -m 0600 "$profile" /etc/linkforge/profile.json
else
    /usr/local/bin/linkforge enroll \
        -url "$enrollment_url" \
        -code-env LINKFORGE_ACTIVATION_CODE \
        -device-name "$(hostname)" \
        -output /etc/linkforge/profile.json
fi
install -o root -g root -m 0644 "$script_dir/linkforge-client-app.service" \
    /etc/systemd/system/linkforge-client-app.service
install -o root -g root -m 0644 "$script_dir/linkforge.desktop" \
    /usr/share/applications/linkforge.desktop

systemctl daemon-reload
systemctl enable --now linkforge-client-app.service
systemctl is-active --quiet linkforge-client-app.service

echo "LinkForge installed. Open LinkForge from the application menu,"
echo "or browse to http://127.0.0.1:9090/ and click Aggregate traffic."
