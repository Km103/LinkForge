package controlplane

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Km103/LinkForge/internal/config"
)

type Hooks struct {
	Authorize func(config.ClientCredential) error
	Revoke    func(string)
}

type Service struct {
	settings   config.Management
	store      *Store
	adminToken []byte
	hooks      Hooks
	logger     *slog.Logger
	limiter    *rateLimiter
}

type enrollmentRequest struct {
	Code       string `json:"code"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
}

type enrollmentResponse struct {
	Profile config.Client `json:"profile"`
}

type activationRequest struct {
	UserID     string `json:"user_id"`
	DeviceName string `json:"device_name"`
	ExpiresIn  string `json:"expires_in,omitempty"`
}

type activationResponse struct {
	ActivationCode string    `json:"activation_code"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func NewService(settings config.Management, store *Store, adminToken string, hooks Hooks, logger *slog.Logger) (*Service, error) {
	if store == nil {
		return nil, errors.New("control-plane store is required")
	}
	if len(adminToken) < 32 {
		return nil, errors.New("control-plane admin token must contain at least 32 characters")
	}
	if hooks.Authorize == nil || hooks.Revoke == nil {
		return nil, errors.New("control-plane relay hooks are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		settings:   settings,
		store:      store,
		adminToken: []byte(adminToken),
		hooks:      hooks,
		logger:     logger.With("component", "control-plane"),
		limiter:    newRateLimiter(),
	}, nil
}

func (s *Service) LoadCredentials() error {
	credentials, err := s.store.ActiveCredentials()
	if err != nil {
		return err
	}
	for _, credential := range credentials {
		if err := s.hooks.Authorize(credential); err != nil {
			return fmt.Errorf("authorize stored client %s: %w", credential.ClientID, err)
		}
	}
	s.logger.Info("managed credentials loaded", "devices", len(credentials))
	return nil
}

func (s *Service) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:              s.settings.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("enrollment API listening", "address", s.settings.Listen)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/healthz", s.health)
	mux.HandleFunc("/v1/enroll", s.enroll)
	mux.HandleFunc("/v1/admin/activations", s.requireAdmin(s.createActivation))
	mux.HandleFunc("/v1/admin/devices", s.requireAdmin(s.listDevices))
	mux.HandleFunc("/v1/admin/devices/", s.requireAdmin(s.deviceAction))
	return s.securityHeaders(mux)
}

func (s *Service) health(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) createActivation(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var input activationRequest
	if err := decodeJSON(w, request, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl := s.settings.ActivationTTL.Value(15 * time.Minute)
	if input.ExpiresIn != "" {
		parsed, err := time.ParseDuration(input.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_in must be a duration such as 15m")
			return
		}
		ttl = parsed
	}
	code, activation, err := s.store.CreateActivation(input.UserID, input.DeviceName, ttl, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Info("activation created", "user_id", activation.UserID, "device_name", activation.DeviceName, "expires_at", activation.ExpiresAt)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, activationResponse{ActivationCode: code, ExpiresAt: activation.ExpiresAt})
}

func (s *Service) enroll(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.limiter.Allow(clientAddress(request), 20, time.Minute, time.Now()) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many enrollment attempts")
		return
	}
	var input enrollmentRequest
	if err := decodeJSON(w, request, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	device, psk, err := s.store.Enroll(input.Code, input.DeviceName, input.Platform, time.Now())
	if errors.Is(err, ErrInvalidActivation) {
		s.logger.Warn("enrollment rejected", "remote", clientAddress(request))
		writeError(w, http.StatusUnauthorized, ErrInvalidActivation.Error())
		return
	}
	if err != nil {
		s.logger.Error("enrollment failed", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}
	credential := credentialFor(device, psk)
	if err := s.hooks.Authorize(credential); err != nil {
		_, _ = s.store.Revoke(device.ClientID, time.Now())
		s.logger.Error("new device could not be authorized", "client_id", device.ClientID, "error", err)
		writeError(w, http.StatusInternalServerError, "device authorization failed")
		return
	}
	profile := s.profileFor(device, psk)
	s.logger.Info("device enrolled",
		"client_id", device.ClientID,
		"user_id", device.UserID,
		"device_name", device.Name,
		"platform", device.Platform,
		"tunnel_address", device.TunnelAddress,
	)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, enrollmentResponse{Profile: profile})
}

func (s *Service) listDevices(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	devices, err := s.store.ListDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].CreatedAt.Before(devices[j].CreatedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *Service) deviceAction(w http.ResponseWriter, request *http.Request) {
	suffix := strings.TrimPrefix(request.URL.Path, "/v1/admin/devices/")
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	clientID := parts[0]
	if len(parts) == 1 && request.Method == http.MethodDelete {
		device, err := s.store.Revoke(clientID, time.Now())
		if errors.Is(err, ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, ErrDeviceNotFound.Error())
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not revoke device")
			return
		}
		s.hooks.Revoke(clientID)
		s.logger.Info("device revoked", "client_id", clientID, "user_id", device.UserID)
		writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
		return
	}
	if len(parts) == 2 && parts[1] == "rotate-key" && request.Method == http.MethodPost {
		device, psk, err := s.store.Rotate(clientID, time.Now())
		if errors.Is(err, ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, ErrDeviceNotFound.Error())
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.hooks.Authorize(credentialFor(device, psk)); err != nil {
			writeError(w, http.StatusInternalServerError, "could not activate rotated key")
			return
		}
		s.logger.Info("device key rotated", "client_id", clientID, "user_id", device.UserID)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, enrollmentResponse{Profile: s.profileFor(device, psk)})
		return
	}
	if len(parts) == 1 {
		w.Header().Set("Allow", http.MethodDelete)
	} else {
		w.Header().Set("Allow", http.MethodPost)
	}
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (s *Service) profileFor(device Device, psk string) config.Client {
	return config.Client{
		Server:             s.settings.PublicRelay,
		ClientID:           device.ClientID,
		PSK:                psk,
		TunnelName:         "LinkForge",
		TunnelAddress:      device.TunnelAddress,
		MTU:                config.DefaultMTU,
		Paths:              []config.Path{},
		AutoDiscoverPaths:  true,
		Routes:             []string{},
		TrafficMode:        "all",
		ConfigureInterface: true,
		HealthInterval:     config.Duration(config.DefaultHealthInterval),
		StatsInterval:      config.Duration(15 * time.Second),
		HandshakeTimeout:   config.Duration(8 * time.Second),
		ReorderDelay:       config.Duration(80 * time.Millisecond),
		ReorderWindow:      512,
		Logging:            config.Logging{Level: "info", Format: "json"},
		Metrics:            config.Metrics{Listen: "127.0.0.1:9090"},
	}
}

func credentialFor(device Device, psk string) config.ClientCredential {
	return config.ClientCredential{
		Name:          device.Name,
		ClientID:      device.ClientID,
		PSK:           psk,
		TunnelAddress: device.TunnelAddress,
	}
}

func (s *Service) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		prefix := "Bearer "
		header := request.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, prefix)), s.adminToken) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="linkforge-admin"`)
			writeError(w, http.StatusUnauthorized, "admin authorization required")
			return
		}
		next(w, request)
	}
}

func (s *Service) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, request)
	})
}

func decodeJSON(w http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func methodNotAllowed(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func clientAddress(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote != nil && remote.IsLoopback() {
		if forwarded := strings.TrimSpace(strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
			if forwardedIP := net.ParseIP(forwarded); forwardedIP != nil {
				return forwardedIP.String()
			}
		}
	}
	return host
}

type rateWindow struct {
	start time.Time
	count int
}

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{windows: make(map[string]rateWindow)}
}

func (r *rateLimiter) Allow(key string, maximum int, duration time.Duration, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	window, exists := r.windows[key]
	if len(r.windows) >= 4096 {
		for current, value := range r.windows {
			if now.Sub(value.start) >= duration {
				delete(r.windows, current)
			}
		}
		window, exists = r.windows[key]
		if !exists && len(r.windows) >= 4096 {
			return false
		}
	}
	if window.start.IsZero() || now.Sub(window.start) >= duration {
		r.windows[key] = rateWindow{start: now, count: 1}
		return true
	}
	if window.count >= maximum {
		return false
	}
	window.count++
	r.windows[key] = window
	return true
}

func CurrentPlatform() string {
	switch runtime.GOOS {
	case "windows", "linux", "darwin":
		return runtime.GOOS
	default:
		return "other"
	}
}
