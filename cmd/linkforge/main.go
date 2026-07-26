package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/linkforge/linkforge/internal/clientapp"
	"github.com/linkforge/linkforge/internal/config"
	"github.com/linkforge/linkforge/internal/engine"
	"github.com/linkforge/linkforge/internal/logging"
	"github.com/linkforge/linkforge/internal/metrics"
	"github.com/linkforge/linkforge/internal/netconfig"
	"github.com/linkforge/linkforge/internal/protocol"
	"github.com/linkforge/linkforge/internal/tun"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "linkforge:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "app":
		return runApp(args[1:], stderr)
	case "client":
		return runClient(args[1:], stderr)
	case "server":
		return runServer(args[1:], stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	case "interfaces":
		return listInterfaces(stdout)
	case "keygen":
		return keygen(stdout)
	case "version":
		fmt.Fprintf(stdout, "linkforge %s (%s, %s, %s/%s)\n", version, commit, date, runtime.GOOS, runtime.GOARCH)
		return nil
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runApp(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("app", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "profile.json", "managed or self-host connection profile")
	listen := flags.String("listen", "127.0.0.1:9090", "local control panel address")
	open := flags.Bool("open", true, "open the control panel in the default browser")
	if err := flags.Parse(args); err != nil {
		return err
	}
	profile, err := config.LoadClient(*profilePath)
	if err != nil {
		return err
	}
	logger := logging.New(profile.Logging, stderr)
	registry := metrics.New("client")
	manager := clientapp.New(profile, logger, registry)
	if _, err := registry.EnableControl(manager.Control()); err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	if *open {
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := openBrowser("http://" + *listen + "/"); err != nil {
				logger.Info("open the LinkForge control panel", "url", "http://"+*listen+"/", "browser_error", err)
			}
		}()
	}
	logger.Info("LinkForge app ready", "url", "http://"+*listen+"/", "traffic_mode", profile.TrafficMode)
	err = metrics.Serve(ctx, *listen, registry, logger)
	if state := manager.State(); state.State == "running" || state.State == "starting" {
		_ = manager.Stop()
	}
	return err
}

func openBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		command = exec.Command("open", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	return command.Start()
}

func runClient(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "client.json", "path to client JSON configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	c, err := config.LoadClient(*path)
	if err != nil {
		return err
	}
	logger := logging.New(c.Logging, stderr)
	paths, err := c.DiscoverPaths()
	if err != nil || len(paths) == 0 {
		return errors.New("no usable physical network paths were discovered")
	}
	c.Paths = paths
	c.AutoDiscoverPaths = false
	ctx, stop := signalContext()
	defer stop()
	var guard *netconfig.RouteGuard
	if c.TrafficMode == "all" {
		physical := make([]netconfig.PhysicalPath, 0, len(paths))
		for _, path := range paths {
			physical = append(physical, netconfig.PhysicalPath{Name: path.Name, Interface: path.Interface, LocalAddress: path.LocalAddress})
		}
		guard, err = netconfig.ProtectRelay(ctx, c.Server, physical, logger)
		if err != nil {
			return privilegeHint(err)
		}
		defer guard.Close(context.Background())
	}
	device, err := tun.Open(c.TunnelName, c.MTU)
	if err != nil {
		return privilegeHint(err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = device.Close()
		}
	}()

	if c.ConfigureInterface {
		if err := netconfig.Setup(ctx, device.Name(), c.TunnelAddress, c.MTU, c.EffectiveRoutes(), logger); err != nil {
			return privilegeHint(err)
		}
	}
	registry := metrics.New("client")
	client, err := engine.NewClient(c, device, logger, registry)
	if err != nil {
		return err
	}
	cleanup = false // engine owns the device
	return runServices(ctx, stop, c.Metrics.Listen, registry, logger, client.Run)
}

func runServer(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "server.json", "path to server JSON configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	c, err := config.LoadServer(*path)
	if err != nil {
		return err
	}
	logger := logging.New(c.Logging, stderr)
	device, err := tun.Open(c.TunnelName, c.MTU)
	if err != nil {
		return privilegeHint(err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = device.Close()
		}
	}()

	ctx, stop := signalContext()
	defer stop()
	if c.ConfigureInterface {
		if err := netconfig.Setup(ctx, device.Name(), c.TunnelAddress, c.MTU, nil, logger); err != nil {
			return privilegeHint(err)
		}
	}
	registry := metrics.New("server")
	server, err := engine.NewServer(c, device, logger, registry)
	if err != nil {
		return err
	}
	cleanup = false // engine owns the device
	return runServices(ctx, stop, c.Metrics.Listen, registry, logger, server.Run)
}

func runDoctor(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "client.json", "path to client JSON configuration")
	duration := flags.Duration("duration", 5*time.Second, "per-path echo load-test duration")
	payloadSize := flags.Int("payload-size", 1000, "diagnostic UDP payload size")
	if err := flags.Parse(args); err != nil {
		return err
	}
	c, err := config.LoadClient(*path)
	if err != nil {
		return err
	}
	logger := logging.New(c.Logging, stderr)
	registry := metrics.New("doctor")
	client, err := engine.NewClient(c, nil, logger, registry)
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	result, err := client.Diagnose(ctx, *duration, *payloadSize)
	if err != nil {
		return err
	}
	type displayPath struct {
		Name              string  `json:"name"`
		LocalAddress      string  `json:"local_address"`
		RTTMilliseconds   float64 `json:"rtt_ms"`
		UploadMbps        float64 `json:"upload_mbps"`
		EchoMbps          float64 `json:"echo_mbps"`
		SentBytes         uint64  `json:"sent_bytes"`
		ReceivedBytes     uint64  `json:"received_bytes"`
		RecommendedWeight float64 `json:"recommended_weight"`
		Healthy           bool    `json:"healthy"`
	}
	type displayResult struct {
		DurationSeconds      float64       `json:"duration_seconds"`
		AggregateUploadMbps  float64       `json:"aggregate_upload_mbps"`
		AggregateEchoMbps    float64       `json:"aggregate_echo_mbps"`
		SentBytes            uint64        `json:"sent_bytes"`
		ReceivedBytes        uint64        `json:"received_bytes"`
		ExpectedPaths        int           `json:"expected_paths"`
		ConnectedPaths       int           `json:"connected_paths"`
		Paths                []displayPath `json:"paths"`
		ConnectivityVerified bool          `json:"connectivity_verified"`
		BondingVerified      bool          `json:"bonding_verified"`
		AllPathsVerified     bool          `json:"all_paths_verified"`
	}
	seconds := result.Duration.Seconds()
	expectedPaths, _ := c.DiscoverPaths()
	healthy := healthyPathCount(result.Paths)
	display := displayResult{
		DurationSeconds:      seconds,
		AggregateUploadMbps:  float64(result.SentBytes*8) / seconds / 1_000_000,
		AggregateEchoMbps:    float64(result.ReceivedBytes*8) / seconds / 1_000_000,
		SentBytes:            result.SentBytes,
		ReceivedBytes:        result.ReceivedBytes,
		ExpectedPaths:        len(expectedPaths),
		ConnectedPaths:       len(result.Paths),
		ConnectivityVerified: result.ReceivedBytes > 0 && healthy > 0,
		BondingVerified:      result.ReceivedBytes > 0 && healthy > 1,
		AllPathsVerified:     len(expectedPaths) > 0 && healthy == len(expectedPaths),
	}
	minEcho := math.MaxFloat64
	for _, path := range result.Paths {
		if path.Healthy && path.ReceivedBytes > 0 {
			rate := float64(path.ReceivedBytes*8) / seconds / 1_000_000
			if rate < minEcho {
				minEcho = rate
			}
		}
	}
	for _, path := range result.Paths {
		echo := float64(path.ReceivedBytes*8) / seconds / 1_000_000
		weight := 0.0
		if minEcho != math.MaxFloat64 && echo > 0 {
			weight = math.Round((echo/minEcho)*10) / 10
		}
		display.Paths = append(display.Paths, displayPath{
			Name:              path.Name,
			LocalAddress:      path.LocalAddress,
			RTTMilliseconds:   float64(path.RTT) / float64(time.Millisecond),
			UploadMbps:        float64(path.SentBytes*8) / seconds / 1_000_000,
			EchoMbps:          echo,
			SentBytes:         path.SentBytes,
			ReceivedBytes:     path.ReceivedBytes,
			RecommendedWeight: weight,
			Healthy:           path.Healthy,
		})
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(display)
}

func healthyPathCount(paths []engine.PathDiagnostic) int {
	count := 0
	for _, path := range paths {
		if path.Healthy && path.ReceivedBytes > 0 {
			count++
		}
	}
	return count
}

func runServices(
	parent context.Context,
	cancel context.CancelFunc,
	metricsListen string,
	registry *metrics.Registry,
	logger *slog.Logger,
	application func(context.Context) error,
) error {
	ctx, stop := context.WithCancel(parent)
	defer stop()
	errCh := make(chan error, 2)
	go func() { errCh <- application(ctx) }()
	serviceCount := 1
	if metricsListen != "" {
		serviceCount++
		go func() { errCh <- metrics.Serve(ctx, metricsListen, registry, logger) }()
	}
	for i := 0; i < serviceCount; i++ {
		err := <-errCh
		stop()
		cancel()
		if err != nil {
			return err
		}
		if parent.Err() != nil {
			return nil
		}
	}
	return nil
}

func listInterfaces(stdout io.Writer) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tSTATE\tMTU\tADDRESSES")
	for _, iface := range interfaces {
		addresses, _ := iface.Addrs()
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}
		fmt.Fprintf(writer, "%s\t%s\t%d\t", iface.Name, state, iface.MTU)
		for i, address := range addresses {
			if i > 0 {
				fmt.Fprint(writer, ", ")
			}
			fmt.Fprint(writer, address.String())
		}
		fmt.Fprintln(writer)
	}
	return writer.Flush()
}

func keygen(stdout io.Writer) error {
	key, err := protocol.GenerateKey()
	if err != nil {
		return err
	}
	clientID, err := protocol.GenerateClientID()
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{
		"client_id": clientID,
		"psk":       key,
	})
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func privilegeHint(err error) error {
	switch runtime.GOOS {
	case "windows":
		return fmt.Errorf("%w (run LinkForge from an Administrator terminal)", err)
	case "linux":
		return fmt.Errorf("%w (run as root or grant CAP_NET_ADMIN)", err)
	default:
		return err
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `LinkForge - encrypted multi-connection bandwidth bonding

Usage:
  linkforge app        -profile profile.json
  linkforge server     -config server.json
  linkforge client     -config client.json
  linkforge doctor     -config client.json [-duration 5s]
  linkforge interfaces
  linkforge keygen
  linkforge version

The app/client and server commands require Administrator on Windows or
CAP_NET_ADMIN/root on Linux. Normal users click Aggregate traffic in the app;
the doctor command does not create a TUN device.`)
}
