package netconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type Runner func(context.Context, string, ...string) ([]byte, error)

type PhysicalPath struct {
	Name         string
	Interface    string
	LocalAddress string
}

type RouteGuard struct {
	runner  Runner
	logger  *slog.Logger
	mu      sync.Mutex
	closed  bool
	cleanup []command
}

type command struct {
	name string
	args []string
}

func Setup(ctx context.Context, interfaceName, address string, mtu int, routes []string, logger *slog.Logger) error {
	return setup(ctx, interfaceName, address, mtu, routes, logger, run)
}

func run(ctx context.Context, command string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, command, args...).CombinedOutput()
}

// ProtectRelay installs per-source physical routing before a full-tunnel route
// is added. This prevents LinkForge's encrypted UDP packets from entering its
// own TUN and preserves a separate route for every uplink.
func ProtectRelay(ctx context.Context, server string, paths []PhysicalPath, logger *slog.Logger) (*RouteGuard, error) {
	return protectRelay(ctx, server, paths, logger, run)
}

func protectRelay(ctx context.Context, server string, paths []PhysicalPath, logger *slog.Logger, runner Runner) (*RouteGuard, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("relay address: %w", err)
	}
	addresses, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolve relay host: %w", err)
	}
	var relays []string
	seenRelay := make(map[string]bool)
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil && !seenRelay[ipv4.String()] {
			relays = append(relays, ipv4.String())
			seenRelay[ipv4.String()] = true
		}
	}
	if len(relays) == 0 {
		return nil, errors.New("relay has no IPv4 address")
	}
	guard := &RouteGuard{runner: runner, logger: logger}
	switch runtime.GOOS {
	case "linux":
		if err := guard.protectLinux(ctx, relays, paths); err != nil {
			guard.Close(context.Background())
			return nil, err
		}
	case "windows":
		if err := guard.protectWindows(ctx, relays, paths); err != nil {
			guard.Close(context.Background())
			return nil, err
		}
	default:
		return nil, fmt.Errorf("automatic relay bypass is unsupported on %s", runtime.GOOS)
	}
	return guard, nil
}

func (g *RouteGuard) protectLinux(ctx context.Context, relays []string, paths []PhysicalPath) error {
	seen := make(map[string]bool)
	for _, path := range paths {
		if path.Interface == "" || path.LocalAddress == "" {
			return fmt.Errorf("path %q needs interface and local address for automatic full-tunnel routing", path.Name)
		}
		key := path.Interface + "/" + path.LocalAddress
		if seen[key] {
			continue
		}
		seen[key] = true
		iface, err := net.InterfaceByName(path.Interface)
		if err != nil {
			return err
		}
		table := strconv.Itoa(20000 + iface.Index)
		priority := strconv.Itoa(20000 + iface.Index)
		output, err := g.runner(ctx, "ip", "-4", "route", "show", "default", "dev", path.Interface)
		if err != nil || strings.TrimSpace(string(output)) == "" {
			return fmt.Errorf("path %q has no IPv4 default route on %s: %w", path.Name, path.Interface, err)
		}
		gateway := tokenAfter(strings.Fields(string(output)), "via")
		_, _ = g.runner(ctx, "ip", "rule", "del", "priority", priority)
		_, _ = g.runner(ctx, "ip", "route", "flush", "table", table)
		args := []string{"route", "replace", "table", table, "default"}
		if gateway != "" {
			args = append(args, "via", gateway)
		}
		args = append(args, "dev", path.Interface, "src", path.LocalAddress)
		if gateway != "" {
			args = append(args, "onlink")
		}
		if output, err := g.runner(ctx, "ip", args...); err != nil {
			return fmt.Errorf("create physical route table for %s: %w: %s", path.Name, err, output)
		}
		if output, err := g.runner(ctx, "ip", "rule", "add", "priority", priority, "from", path.LocalAddress+"/32", "table", table); err != nil {
			return fmt.Errorf("create source rule for %s: %w: %s", path.Name, err, output)
		}
		g.cleanup = append(g.cleanup,
			command{name: "ip", args: []string{"rule", "del", "priority", priority}},
			command{name: "ip", args: []string{"route", "flush", "table", table}},
		)
		g.logger.Info("physical relay route protected", "path", path.Name, "interface", path.Interface, "source", path.LocalAddress, "gateway", gateway, "relay_addresses", relays)
	}
	return nil
}

func (g *RouteGuard) protectWindows(ctx context.Context, relays []string, paths []PhysicalPath) error {
	for _, path := range paths {
		if path.Interface == "" {
			return fmt.Errorf("path %q needs an interface for automatic full-tunnel routing", path.Name)
		}
		iface, err := net.InterfaceByName(path.Interface)
		if err != nil {
			return err
		}
		gatewayScript := fmt.Sprintf("(Get-NetIPConfiguration -InterfaceIndex %d).IPv4DefaultGateway.NextHop", iface.Index)
		output, err := g.runner(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", gatewayScript)
		if err != nil || strings.TrimSpace(string(output)) == "" {
			return fmt.Errorf("path %q has no IPv4 gateway: %w", path.Name, err)
		}
		gateway := strings.TrimSpace(string(output))
		for _, relay := range relays {
			script := fmt.Sprintf("if (-not (Get-NetRoute -DestinationPrefix '%s/32' -InterfaceIndex %d -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '%s/32' -InterfaceIndex %d -NextHop '%s' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; 'created' }", relay, iface.Index, relay, iface.Index, gateway)
			created, err := g.runner(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
			if err != nil {
				return fmt.Errorf("protect relay route for %s: %w: %s", path.Name, err, created)
			}
			if strings.Contains(string(created), "created") {
				cleanup := fmt.Sprintf("Remove-NetRoute -DestinationPrefix '%s/32' -InterfaceIndex %d -Confirm:$false -ErrorAction SilentlyContinue", relay, iface.Index)
				g.cleanup = append(g.cleanup, command{name: "powershell.exe", args: []string{"-NoProfile", "-NonInteractive", "-Command", cleanup}})
			}
		}
		g.logger.Info("physical relay route protected", "path", path.Name, "interface", path.Interface, "source", path.LocalAddress, "gateway", gateway, "relay_addresses", relays)
	}
	return nil
}

func (g *RouteGuard) Close(ctx context.Context) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	cleanup := append([]command(nil), g.cleanup...)
	g.mu.Unlock()
	for index := len(cleanup) - 1; index >= 0; index-- {
		command := cleanup[index]
		if output, err := g.runner(ctx, command.name, command.args...); err != nil {
			g.logger.Warn("relay route cleanup failed", "command", command.name, "args", command.args, "error", err, "output", string(output))
		}
	}
}

func tokenAfter(tokens []string, target string) string {
	for index := 0; index+1 < len(tokens); index++ {
		if tokens[index] == target {
			return tokens[index+1]
		}
	}
	return ""
}

func setup(ctx context.Context, interfaceName, address string, mtu int, routes []string, logger *slog.Logger, runner Runner) error {
	switch runtime.GOOS {
	case "linux":
		commands := [][]string{
			{"ip", "link", "set", "dev", interfaceName, "mtu", strconv.Itoa(mtu), "up"},
			{"ip", "address", "replace", address, "dev", interfaceName},
		}
		for _, route := range routes {
			commands = append(commands, []string{"ip", "route", "replace", route, "dev", interfaceName})
		}
		for _, args := range commands {
			if output, err := runner(ctx, args[0], args[1:]...); err != nil {
				return fmt.Errorf("%v failed: %w: %s", args, err, output)
			}
			logger.Debug("network configuration applied", "command", args)
		}
		return nil
	case "windows":
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return err
		}
		mask := netmask(prefix.Bits())
		commands := [][]string{
			{"netsh", "interface", "ipv4", "set", "address", "name=" + interfaceName, "source=static", "address=" + prefix.Addr().String(), "mask=" + mask, "gateway=none", "store=active"},
			{"netsh", "interface", "ipv4", "set", "subinterface", interfaceName, "mtu=" + strconv.Itoa(mtu), "store=active"},
		}
		for _, route := range routes {
			commands = append(commands, []string{"netsh", "interface", "ipv4", "add", "route", route, interfaceName, "nexthop=0.0.0.0", "store=active"})
		}
		for _, args := range commands {
			if output, err := runner(ctx, args[0], args[1:]...); err != nil {
				return fmt.Errorf("%v failed: %w: %s", args, err, output)
			}
			logger.Debug("network configuration applied", "command", args)
		}
		return nil
	default:
		return fmt.Errorf("automatic TUN configuration is unsupported on %s", runtime.GOOS)
	}
}

func netmask(bits int) string {
	var raw [4]byte
	for i := 0; i < bits; i++ {
		raw[i/8] |= 1 << (7 - (i % 8))
	}
	return netip.AddrFrom4(raw).String()
}
