package metrics

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Path struct {
	SentPackets     atomic.Uint64
	SentBytes       atomic.Uint64
	ReceivedPackets atomic.Uint64
	ReceivedBytes   atomic.Uint64
	AuthFailures    atomic.Uint64
	ReplayDrops     atomic.Uint64
	WriteErrors     atomic.Uint64
	RTTNanos        atomic.Int64
	Healthy         atomic.Bool
}

type Registry struct {
	Role            string
	Started         time.Time
	SentPackets     atomic.Uint64
	SentBytes       atomic.Uint64
	ReceivedPackets atomic.Uint64
	ReceivedBytes   atomic.Uint64
	InvalidPackets  atomic.Uint64
	AuthFailures    atomic.Uint64
	NoPathDrops     atomic.Uint64
	ReorderSkips    atomic.Uint64
	TUNReadErrors   atomic.Uint64
	TUNWriteErrors  atomic.Uint64
	ActiveSessions  atomic.Int64
	ready           atomic.Bool
	mu              sync.RWMutex
	paths           map[string]*Path
	control         *Control
	controlToken    string
}

type ControlStatus struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

type Control struct {
	Start func() error
	Stop  func() error
	State func() ControlStatus
}

func New(role string) *Registry {
	return &Registry{Role: role, Started: time.Now(), paths: make(map[string]*Path)}
}

func (r *Registry) SetReady(ready bool) { r.ready.Store(ready) }

func (r *Registry) IsReady() bool { return r.ready.Load() }

func (r *Registry) EnableControl(control *Control) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	r.control = control
	r.controlToken = base64.RawURLEncoding.EncodeToString(raw)
	return r.controlToken, nil
}

func (r *Registry) Path(name string) *Path {
	r.mu.RLock()
	path := r.paths[name]
	r.mu.RUnlock()
	if path != nil {
		return path
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if path = r.paths[name]; path == nil {
		path = &Path{}
		r.paths[name] = path
	}
	return path
}

func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.serveDashboard)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !r.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready"}` + "\n"))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready"}` + "\n"))
	})
	mux.HandleFunc("/metrics", r.serveMetrics)
	mux.HandleFunc("/api/v1/status", r.serveStatus)
	mux.HandleFunc("/api/v1/control/start", r.serveControl)
	mux.HandleFunc("/api/v1/control/stop", r.serveControl)
	return mux
}

type Status struct {
	Role            string         `json:"role"`
	Ready           bool           `json:"ready"`
	UptimeSeconds   float64        `json:"uptime_seconds"`
	SentBytes       uint64         `json:"sent_bytes"`
	ReceivedBytes   uint64         `json:"received_bytes"`
	SentPackets     uint64         `json:"sent_packets"`
	ReceivedPackets uint64         `json:"received_packets"`
	InvalidPackets  uint64         `json:"invalid_packets"`
	AuthFailures    uint64         `json:"auth_failures"`
	NoPathDrops     uint64         `json:"no_path_drops"`
	ReorderSkips    uint64         `json:"reorder_skips"`
	TUNReadErrors   uint64         `json:"tun_read_errors"`
	TUNWriteErrors  uint64         `json:"tun_write_errors"`
	ActiveSessions  int64          `json:"active_sessions"`
	Paths           []PathStatus   `json:"paths"`
	Control         *ControlStatus `json:"control,omitempty"`
}

type PathStatus struct {
	Name            string  `json:"name"`
	Healthy         bool    `json:"healthy"`
	RTTMilliseconds float64 `json:"rtt_ms"`
	SentBytes       uint64  `json:"sent_bytes"`
	ReceivedBytes   uint64  `json:"received_bytes"`
	SentPackets     uint64  `json:"sent_packets"`
	ReceivedPackets uint64  `json:"received_packets"`
	AuthFailures    uint64  `json:"auth_failures"`
	ReplayDrops     uint64  `json:"replay_drops"`
	WriteErrors     uint64  `json:"write_errors"`
}

func (r *Registry) Snapshot() Status {
	status := Status{
		Role:            r.Role,
		Ready:           r.ready.Load(),
		UptimeSeconds:   time.Since(r.Started).Seconds(),
		SentBytes:       r.SentBytes.Load(),
		ReceivedBytes:   r.ReceivedBytes.Load(),
		SentPackets:     r.SentPackets.Load(),
		ReceivedPackets: r.ReceivedPackets.Load(),
		InvalidPackets:  r.InvalidPackets.Load(),
		AuthFailures:    r.AuthFailures.Load(),
		NoPathDrops:     r.NoPathDrops.Load(),
		ReorderSkips:    r.ReorderSkips.Load(),
		TUNReadErrors:   r.TUNReadErrors.Load(),
		TUNWriteErrors:  r.TUNWriteErrors.Load(),
		ActiveSessions:  r.ActiveSessions.Load(),
		Paths:           make([]PathStatus, 0, len(r.paths)),
	}
	if r.control != nil && r.control.State != nil {
		controlStatus := r.control.State()
		status.Control = &controlStatus
	}
	r.mu.RLock()
	names := make([]string, 0, len(r.paths))
	for name := range r.paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := r.paths[name]
		status.Paths = append(status.Paths, PathStatus{
			Name:            name,
			Healthy:         path.Healthy.Load(),
			RTTMilliseconds: float64(path.RTTNanos.Load()) / float64(time.Millisecond),
			SentBytes:       path.SentBytes.Load(),
			ReceivedBytes:   path.ReceivedBytes.Load(),
			SentPackets:     path.SentPackets.Load(),
			ReceivedPackets: path.ReceivedPackets.Load(),
			AuthFailures:    path.AuthFailures.Load(),
			ReplayDrops:     path.ReplayDrops.Load(),
			WriteErrors:     path.WriteErrors.Load(),
		})
	}
	r.mu.RUnlock()
	return status
}

func (r *Registry) serveStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(r.Snapshot())
}

func (r *Registry) serveDashboard(w http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" && request.URL.Path != "/dashboard" {
		http.NotFound(w, request)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	page := strings.Replace(dashboardHTML, "__CONTROL_TOKEN__", r.controlToken, 1)
	_, _ = w.Write([]byte(page))
}

func (r *Registry) serveControl(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.control == nil || request.Method != http.MethodPost || subtle.ConstantTimeCompare([]byte(request.Header.Get("X-LinkForge-Control")), []byte(r.controlToken)) != 1 {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "control request rejected"})
		return
	}
	var err error
	if strings.HasSuffix(request.URL.Path, "/start") && r.control.Start != nil {
		err = r.control.Start()
	} else if strings.HasSuffix(request.URL.Path, "/stop") && r.control.Stop != nil {
		err = r.control.Stop()
	} else {
		err = errors.New("control action is unavailable")
	}
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (r *Registry) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	role := quote(r.Role)
	metric(w, "linkforge_uptime_seconds", "Process uptime.", nil, time.Since(r.Started).Seconds())
	metric(w, "linkforge_sent_packets_total", "Encrypted packets sent.", map[string]string{"role": role}, r.SentPackets.Load())
	metric(w, "linkforge_sent_bytes_total", "Encrypted payload bytes sent.", map[string]string{"role": role}, r.SentBytes.Load())
	metric(w, "linkforge_received_packets_total", "Authenticated packets received.", map[string]string{"role": role}, r.ReceivedPackets.Load())
	metric(w, "linkforge_received_bytes_total", "Authenticated payload bytes received.", map[string]string{"role": role}, r.ReceivedBytes.Load())
	metric(w, "linkforge_invalid_packets_total", "Malformed packets dropped.", map[string]string{"role": role}, r.InvalidPackets.Load())
	metric(w, "linkforge_auth_failures_total", "Authentication failures.", map[string]string{"role": role}, r.AuthFailures.Load())
	metric(w, "linkforge_no_path_drops_total", "Packets dropped because no healthy path existed.", map[string]string{"role": role}, r.NoPathDrops.Load())
	metric(w, "linkforge_reorder_skips_total", "Missing global packet sequences skipped after the reorder deadline.", map[string]string{"role": role}, r.ReorderSkips.Load())
	metric(w, "linkforge_tun_read_errors_total", "TUN read failures.", map[string]string{"role": role}, r.TUNReadErrors.Load())
	metric(w, "linkforge_tun_write_errors_total", "TUN write failures.", map[string]string{"role": role}, r.TUNWriteErrors.Load())
	metric(w, "linkforge_active_sessions", "Currently active client sessions.", map[string]string{"role": role}, r.ActiveSessions.Load())

	r.mu.RLock()
	names := make([]string, 0, len(r.paths))
	for name := range r.paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := r.paths[name]
		labels := map[string]string{"role": role, "path": quote(name)}
		metric(w, "linkforge_path_sent_packets_total", "Packets sent on a path.", labels, p.SentPackets.Load())
		metric(w, "linkforge_path_sent_bytes_total", "Payload bytes sent on a path.", labels, p.SentBytes.Load())
		metric(w, "linkforge_path_received_packets_total", "Packets received on a path.", labels, p.ReceivedPackets.Load())
		metric(w, "linkforge_path_received_bytes_total", "Payload bytes received on a path.", labels, p.ReceivedBytes.Load())
		metric(w, "linkforge_path_auth_failures_total", "Authentication failures by path.", labels, p.AuthFailures.Load())
		metric(w, "linkforge_path_replay_drops_total", "Replay-window drops by path.", labels, p.ReplayDrops.Load())
		metric(w, "linkforge_path_write_errors_total", "Socket write errors by path.", labels, p.WriteErrors.Load())
		healthy := uint64(0)
		if p.Healthy.Load() {
			healthy = 1
		}
		metric(w, "linkforge_path_healthy", "Whether the path is healthy.", labels, healthy)
		metric(w, "linkforge_path_rtt_seconds", "Last smoothed path RTT.", labels, float64(p.RTTNanos.Load())/float64(time.Second))
	}
	r.mu.RUnlock()
}

func metric(w http.ResponseWriter, name, help string, labels map[string]string, value any) {
	if help != "" {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	fmt.Fprint(w, name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for key := range labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		fmt.Fprint(w, "{")
		for i, key := range keys {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `%s="%s"`, key, labels[key])
		}
		fmt.Fprint(w, "}")
	}
	fmt.Fprintln(w, " "+formatValue(value))
}

func formatValue(value any) string {
	switch v := value.(type) {
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case uint64:
		return strconv.FormatUint(v, 10)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		return fmt.Sprint(v)
	}
}

func quote(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value)
}

func Serve(ctx context.Context, listen string, registry *Registry, logger *slog.Logger) error {
	if listen == "" {
		return nil
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           registry.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("metrics server listening", "address", listen)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
