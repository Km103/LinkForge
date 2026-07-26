package clientapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/linkforge/linkforge/internal/config"
	"github.com/linkforge/linkforge/internal/engine"
	"github.com/linkforge/linkforge/internal/metrics"
	"github.com/linkforge/linkforge/internal/netconfig"
	"github.com/linkforge/linkforge/internal/tun"
)

type Manager struct {
	profile config.Client
	logger  *slog.Logger
	metrics *metrics.Registry

	mu      sync.Mutex
	state   string
	lastErr string
	cancel  context.CancelFunc
	done    chan struct{}
	cached  []config.Path
}

func New(profile config.Client, logger *slog.Logger, registry *metrics.Registry) *Manager {
	return &Manager{profile: profile, logger: logger, metrics: registry, state: "stopped"}
}

func (m *Manager) Control() *metrics.Control {
	return &metrics.Control{Start: m.Start, Stop: m.Stop, State: m.State}
}

func (m *Manager) State() metrics.ControlStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.state
	if state == "starting" && m.metrics.IsReady() {
		state = "running"
	}
	return metrics.ControlStatus{State: state, Error: m.lastErr}
}

func (m *Manager) Start() error {
	m.mu.Lock()
	if m.state == "starting" || m.state == "running" || m.state == "stopping" {
		m.mu.Unlock()
		return errors.New("aggregation is already active")
	}
	m.state = "calibrating"
	m.lastErr = ""
	m.mu.Unlock()

	profile := m.profile
	paths, err := profile.DiscoverPaths()
	if err != nil || len(paths) == 0 {
		return m.startFailed(errors.New("no usable Ethernet, Wi-Fi, or tethering interface was discovered"))
	}
	profile.Paths = paths
	profile.AutoDiscoverPaths = false
	calibrated, err := m.calibrate(profile, paths)
	if err != nil {
		return m.startFailed(err)
	}
	profile.Paths = calibrated
	paths = calibrated
	m.mu.Lock()
	m.state = "starting"
	m.mu.Unlock()

	var guard *netconfig.RouteGuard
	if profile.TrafficMode == "all" {
		physical := make([]netconfig.PhysicalPath, 0, len(paths))
		for _, path := range paths {
			physical = append(physical, netconfig.PhysicalPath{Name: path.Name, Interface: path.Interface, LocalAddress: path.LocalAddress})
		}
		guard, err = netconfig.ProtectRelay(context.Background(), profile.Server, physical, m.logger)
		if err != nil {
			return m.startFailed(err)
		}
	}
	device, err := tun.Open(profile.TunnelName, profile.MTU)
	if err != nil {
		if guard != nil {
			guard.Close(context.Background())
		}
		return m.startFailed(err)
	}
	if profile.ConfigureInterface {
		if err := netconfig.Setup(context.Background(), device.Name(), profile.TunnelAddress, profile.MTU, profile.EffectiveRoutes(), m.logger); err != nil {
			_ = device.Close()
			if guard != nil {
				guard.Close(context.Background())
			}
			return m.startFailed(err)
		}
	}
	client, err := engine.NewClient(profile, device, m.logger, m.metrics)
	if err != nil {
		_ = device.Close()
		if guard != nil {
			guard.Close(context.Background())
		}
		return m.startFailed(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.mu.Lock()
	m.cancel = cancel
	m.done = done
	m.mu.Unlock()
	go func() {
		defer close(done)
		runErr := client.Run(ctx)
		if guard != nil {
			guard.Close(context.Background())
		}
		m.mu.Lock()
		if runErr != nil && ctx.Err() == nil {
			m.state = "error"
			m.lastErr = runErr.Error()
		} else {
			m.state = "stopped"
			m.lastErr = ""
		}
		m.cancel = nil
		m.done = nil
		m.mu.Unlock()
	}()
	m.logger.Info("aggregation requested", "paths", len(paths), "traffic_mode", profile.TrafficMode)
	return nil
}

func (m *Manager) calibrate(profile config.Client, discovered []config.Path) ([]config.Path, error) {
	m.mu.Lock()
	if samePathSet(m.cached, discovered) {
		cached := append([]config.Path(nil), m.cached...)
		m.mu.Unlock()
		return cached, nil
	}
	m.mu.Unlock()
	calibrationMetrics := metrics.New("calibration")
	client, err := engine.NewClient(profile, nil, m.logger, calibrationMetrics)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	result, err := client.Diagnose(ctx, 2*time.Second, 1000)
	if err != nil {
		return nil, fmt.Errorf("link calibration failed: %w", err)
	}
	byName := make(map[string]engine.PathDiagnostic, len(result.Paths))
	minimum := uint64(math.MaxUint64)
	for _, path := range result.Paths {
		if path.Healthy && path.ReceivedBytes > 0 {
			byName[path.Name] = path
			if path.ReceivedBytes < minimum {
				minimum = path.ReceivedBytes
			}
		}
	}
	if len(byName) == 0 || minimum == math.MaxUint64 {
		return nil, errors.New("no path returned encrypted calibration traffic")
	}
	calibrated := make([]config.Path, 0, len(byName))
	for _, path := range discovered {
		measurement, ok := byName[path.Name]
		if !ok {
			continue
		}
		weight := float64(measurement.ReceivedBytes) / float64(minimum)
		weight = math.Round(math.Min(math.Max(weight, 1), 100)*10) / 10
		path.Weight = weight
		calibrated = append(calibrated, path)
		m.logger.Info("path calibrated", "path", path.Name, "local_address", path.LocalAddress, "rtt", measurement.RTT, "weight", weight)
	}
	m.mu.Lock()
	m.cached = append([]config.Path(nil), calibrated...)
	m.mu.Unlock()
	return calibrated, nil
}

func samePathSet(a, b []config.Path) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, path := range a {
		seen[path.Interface+"/"+path.LocalAddress] = true
	}
	for _, path := range b {
		if !seen[path.Interface+"/"+path.LocalAddress] {
			return false
		}
	}
	return true
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	if m.cancel == nil {
		m.mu.Unlock()
		return errors.New("aggregation is not active")
	}
	m.state = "stopping"
	cancel := m.cancel
	done := m.done
	m.mu.Unlock()
	cancel()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("timed out waiting for aggregation cleanup")
	}
}

func (m *Manager) startFailed(err error) error {
	m.mu.Lock()
	m.state = "error"
	m.lastErr = err.Error()
	m.mu.Unlock()
	m.logger.Error("aggregation could not start", "error", err)
	return err
}
