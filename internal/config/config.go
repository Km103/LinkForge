package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/Km103/LinkForge/internal/protocol"
)

const (
	DefaultMTU            = 1280
	DefaultHealthInterval = 2 * time.Second
)

type Logging struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

type Metrics struct {
	Listen string `json:"listen"`
}

type Path struct {
	Name         string  `json:"name"`
	LocalAddress string  `json:"local_address"`
	Interface    string  `json:"interface"`
	Weight       float64 `json:"weight"`
	Enabled      *bool   `json:"enabled,omitempty"`
}

func (p Path) IsEnabled() bool {
	return p.Enabled == nil || *p.Enabled
}

func (p Path) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("path name is required")
	}
	if len(p.Name) > 63 {
		return errors.New("path name cannot exceed 63 bytes")
	}
	if p.Weight < 0 {
		return errors.New("path weight cannot be negative")
	}
	if p.Weight > 655.35 {
		return errors.New("path weight cannot exceed 655.35")
	}
	if p.LocalAddress != "" {
		ip := net.ParseIP(p.LocalAddress)
		if ip == nil {
			return fmt.Errorf("invalid local_address %q", p.LocalAddress)
		}
	}
	return nil
}

type Client struct {
	Server             string   `json:"server"`
	ClientID           string   `json:"client_id"`
	PSK                string   `json:"psk,omitempty"`
	PSKEnv             string   `json:"psk_env,omitempty"`
	TunnelName         string   `json:"tunnel_name"`
	TunnelAddress      string   `json:"tunnel_address"`
	MTU                int      `json:"mtu"`
	Paths              []Path   `json:"paths"`
	AutoDiscoverPaths  bool     `json:"auto_discover_paths"`
	Routes             []string `json:"routes"`
	TrafficMode        string   `json:"traffic_mode"`
	ConfigureInterface bool     `json:"configure_interface"`
	HealthInterval     Duration `json:"health_interval"`
	StatsInterval      Duration `json:"stats_interval"`
	HandshakeTimeout   Duration `json:"handshake_timeout"`
	ReorderDelay       Duration `json:"reorder_delay"`
	ReorderWindow      int      `json:"reorder_window"`
	Logging            Logging  `json:"logging"`
	Metrics            Metrics  `json:"metrics"`
}

type ClientCredential struct {
	Name          string `json:"name"`
	ClientID      string `json:"client_id"`
	PSK           string `json:"psk,omitempty"`
	PSKEnv        string `json:"psk_env,omitempty"`
	TunnelAddress string `json:"tunnel_address"`
}

type Management struct {
	Listen        string   `json:"listen"`
	DatabasePath  string   `json:"database_path"`
	PublicRelay   string   `json:"public_relay"`
	TunnelPool    string   `json:"tunnel_pool"`
	AdminTokenEnv string   `json:"admin_token_env"`
	MasterKeyEnv  string   `json:"master_key_env"`
	ActivationTTL Duration `json:"activation_ttl"`
}

type Server struct {
	Listen             string             `json:"listen"`
	TunnelName         string             `json:"tunnel_name"`
	TunnelAddress      string             `json:"tunnel_address"`
	MTU                int                `json:"mtu"`
	Clients            []ClientCredential `json:"clients"`
	ConfigureInterface bool               `json:"configure_interface"`
	SessionTimeout     Duration           `json:"session_timeout"`
	ReorderDelay       Duration           `json:"reorder_delay"`
	ReorderWindow      int                `json:"reorder_window"`
	StatsInterval      Duration           `json:"stats_interval"`
	Logging            Logging            `json:"logging"`
	Metrics            Metrics            `json:"metrics"`
	Management         *Management        `json:"management,omitempty"`
}

// Duration accepts Go duration strings in JSON while keeping config readable.
type Duration time.Duration

func (d Duration) Value(fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return time.Duration(d)
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) || bytes.Equal(b, []byte(`""`)) {
		*d = 0
		return nil
	}
	var text string
	if err := json.Unmarshal(b, &text); err != nil {
		return errors.New("duration must be a string such as \"2s\"")
	}
	value, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	*d = Duration(value)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func LoadClient(path string) (Client, error) {
	var c Client
	if err := loadStrict(path, &c); err != nil {
		return c, err
	}
	c.defaults()
	return c, c.Validate()
}

func LoadServer(path string) (Server, error) {
	var c Server
	if err := loadStrict(path, &c); err != nil {
		return c, err
	}
	c.defaults()
	return c, c.Validate()
}

func loadStrict(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: multiple JSON values", path)
		}
		return fmt.Errorf("decode %s trailing data: %w", path, err)
	}
	return nil
}

func (c *Client) defaults() {
	if c.TunnelName == "" {
		c.TunnelName = "linkforge0"
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.TrafficMode == "" {
		c.TrafficMode = "manual"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.ReorderWindow == 0 {
		c.ReorderWindow = 512
	}
	for i := range c.Paths {
		if c.Paths[i].Weight == 0 {
			c.Paths[i].Weight = 1
		}
	}
}

func (c Client) Validate() error {
	if _, err := net.ResolveUDPAddr("udp", c.Server); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	if _, err := protocol.ParseClientID(c.ClientID); err != nil {
		return err
	}
	if _, err := c.Key(); err != nil {
		return fmt.Errorf("client key: %w", err)
	}
	if err := validateTunnel(c.TunnelAddress, c.MTU); err != nil {
		return err
	}
	if !c.AutoDiscoverPaths && len(c.Paths) == 0 {
		return errors.New("at least one path is required unless auto_discover_paths is true")
	}
	switch c.TrafficMode {
	case "manual", "all":
	default:
		return errors.New("traffic_mode must be manual or all")
	}
	seen := make(map[string]struct{})
	for _, p := range c.Paths {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("path %q: %w", p.Name, err)
		}
		if _, ok := seen[p.Name]; ok {
			return fmt.Errorf("duplicate path name %q", p.Name)
		}
		seen[p.Name] = struct{}{}
	}
	for _, route := range c.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return fmt.Errorf("route %q: %w", route, err)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("route %q: only IPv4 routes are currently supported", route)
		}
	}
	if c.ReorderWindow < 16 || c.ReorderWindow > 65536 {
		return errors.New("reorder_window must be between 16 and 65536")
	}
	if err := validateDuration("health_interval", c.HealthInterval, 250*time.Millisecond, 5*time.Second); err != nil {
		return err
	}
	if err := validateDuration("handshake_timeout", c.HandshakeTimeout, time.Second, 2*time.Minute); err != nil {
		return err
	}
	if err := validateDuration("reorder_delay", c.ReorderDelay, time.Millisecond, 2*time.Second); err != nil {
		return err
	}
	if err := validateDuration("stats_interval", c.StatsInterval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	return validateLogging(c.Logging)
}

func (s *Server) defaults() {
	if s.Listen == "" {
		s.Listen = ":4430"
	}
	if s.TunnelName == "" {
		s.TunnelName = "linkforge0"
	}
	if s.MTU == 0 {
		s.MTU = DefaultMTU
	}
	if s.Logging.Level == "" {
		s.Logging.Level = "info"
	}
	if s.Logging.Format == "" {
		s.Logging.Format = "json"
	}
	if s.ReorderWindow == 0 {
		s.ReorderWindow = 512
	}
	if s.Management != nil {
		if s.Management.Listen == "" {
			s.Management.Listen = "127.0.0.1:8443"
		}
		if s.Management.DatabasePath == "" {
			s.Management.DatabasePath = "/var/lib/linkforge/control.db"
		}
		if s.Management.TunnelPool == "" {
			if prefix, err := netip.ParsePrefix(s.TunnelAddress); err == nil {
				s.Management.TunnelPool = prefix.Masked().String()
			}
		}
		if s.Management.AdminTokenEnv == "" {
			s.Management.AdminTokenEnv = "LINKFORGE_ADMIN_TOKEN"
		}
		if s.Management.MasterKeyEnv == "" {
			s.Management.MasterKeyEnv = "LINKFORGE_CONTROL_MASTER_KEY"
		}
		if s.Management.ActivationTTL == 0 {
			s.Management.ActivationTTL = Duration(15 * time.Minute)
		}
	}
}

func (s Server) Validate() error {
	if _, err := net.ResolveUDPAddr("udp", s.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if err := validateTunnel(s.TunnelAddress, s.MTU); err != nil {
		return err
	}
	if len(s.Clients) == 0 && s.Management == nil {
		return errors.New("at least one server client credential is required")
	}
	if s.ReorderWindow < 16 || s.ReorderWindow > 65536 {
		return errors.New("reorder_window must be between 16 and 65536")
	}
	if err := validateDuration("reorder_delay", s.ReorderDelay, time.Millisecond, 2*time.Second); err != nil {
		return err
	}
	if err := validateDuration("session_timeout", s.SessionTimeout, 10*time.Second, 24*time.Hour); err != nil {
		return err
	}
	if err := validateDuration("stats_interval", s.StatsInterval, time.Second, 24*time.Hour); err != nil {
		return err
	}
	ids := make(map[string]struct{})
	ips := make(map[netip.Addr]struct{})
	keys := make(map[string]struct{})
	serverPrefix, _ := netip.ParsePrefix(s.TunnelAddress)
	for _, client := range s.Clients {
		id, err := protocol.ParseClientID(client.ClientID)
		if err != nil {
			return fmt.Errorf("server client %q: %w", client.Name, err)
		}
		idText := protocol.ClientIDString(id)
		if _, ok := ids[idText]; ok {
			return fmt.Errorf("duplicate client_id %s", idText)
		}
		ids[idText] = struct{}{}
		key, err := client.Key()
		if err != nil {
			return fmt.Errorf("server client %q key: %w", client.Name, err)
		}
		if _, ok := keys[string(key)]; ok {
			return fmt.Errorf("server client %q reuses another client's key", client.Name)
		}
		keys[string(key)] = struct{}{}
		prefix, err := netip.ParsePrefix(client.TunnelAddress)
		if err != nil {
			return fmt.Errorf("server client %q tunnel_address: %w", client.Name, err)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("server client %q: IPv4 is currently required", client.Name)
		}
		if !serverPrefix.Contains(prefix.Addr()) || prefix.Addr() == serverPrefix.Addr() {
			return fmt.Errorf("server client %q tunnel IP %s is not a usable address inside %s", client.Name, prefix.Addr(), serverPrefix)
		}
		if _, ok := ips[prefix.Addr()]; ok {
			return fmt.Errorf("duplicate client tunnel IP %s", prefix.Addr())
		}
		ips[prefix.Addr()] = struct{}{}
	}
	if s.Management != nil {
		if err := s.Management.Validate(serverPrefix); err != nil {
			return fmt.Errorf("management: %w", err)
		}
	}
	return validateLogging(s.Logging)
}

func (m Management) Validate(serverPrefix netip.Prefix) error {
	host, _, err := net.SplitHostPort(m.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("listen must use a loopback address; terminate HTTPS at a reverse proxy")
		}
	}
	if strings.TrimSpace(m.DatabasePath) == "" {
		return errors.New("database_path is required")
	}
	if strings.TrimSpace(m.PublicRelay) == "" {
		return errors.New("public_relay is required")
	}
	if _, err := net.ResolveUDPAddr("udp", m.PublicRelay); err != nil {
		return fmt.Errorf("public_relay: %w", err)
	}
	pool, err := netip.ParsePrefix(m.TunnelPool)
	if err != nil || !pool.Addr().Is4() {
		return errors.New("tunnel_pool must be an IPv4 prefix")
	}
	if pool.Masked() != serverPrefix.Masked() {
		return fmt.Errorf("tunnel_pool %s must match server tunnel subnet %s", pool.Masked(), serverPrefix.Masked())
	}
	if pool.Bits() > 30 || pool.Bits() < 16 {
		return errors.New("tunnel_pool prefix length must be between /16 and /30")
	}
	if strings.TrimSpace(m.AdminTokenEnv) == "" || strings.TrimSpace(m.MasterKeyEnv) == "" {
		return errors.New("admin_token_env and master_key_env are required")
	}
	return validateDuration("activation_ttl", m.ActivationTTL, time.Minute, 24*time.Hour)
}

func (m Management) Secrets() (string, []byte, error) {
	adminToken := os.Getenv(m.AdminTokenEnv)
	if len(adminToken) < 32 {
		return "", nil, fmt.Errorf("environment variable %s must contain at least 32 characters", m.AdminTokenEnv)
	}
	masterValue := os.Getenv(m.MasterKeyEnv)
	if masterValue == "" {
		return "", nil, fmt.Errorf("environment variable %s is empty", m.MasterKeyEnv)
	}
	masterKey, err := protocol.ParseKey(masterValue)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", m.MasterKeyEnv, err)
	}
	return adminToken, masterKey, nil
}

func validateTunnel(address string, mtu int) error {
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return fmt.Errorf("tunnel_address: %w", err)
	}
	if !prefix.Addr().Is4() {
		return errors.New("only IPv4 tunnel addresses are currently supported")
	}
	if mtu < 576 || mtu > 9000 || mtu > protocol.MaxDataPayload {
		return errors.New("mtu must be between 576 and 9000")
	}
	return nil
}

func validateDuration(name string, value Duration, minimum, maximum time.Duration) error {
	if value == 0 {
		return nil
	}
	duration := time.Duration(value)
	if duration < minimum || duration > maximum {
		return fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return nil
}

func validateLogging(l Logging) error {
	switch strings.ToLower(l.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level must be debug, info, warn, or error")
	}
	switch strings.ToLower(l.Format) {
	case "json", "text":
	default:
		return fmt.Errorf("logging.format must be json or text")
	}
	return nil
}

func resolveKey(value, envName string) ([]byte, error) {
	if value != "" && envName != "" {
		return nil, errors.New("set either psk or psk_env, not both")
	}
	if envName != "" {
		value = os.Getenv(envName)
		if value == "" {
			return nil, fmt.Errorf("environment variable %s is empty", envName)
		}
	}
	return protocol.ParseKey(value)
}

func (c Client) Key() ([]byte, error) {
	return resolveKey(c.PSK, c.PSKEnv)
}

func (c ClientCredential) Key() ([]byte, error) {
	return resolveKey(c.PSK, c.PSKEnv)
}

// DiscoverPaths returns one path for every active non-loopback unicast IP.
// Explicit paths take precedence by address.
func (c Client) DiscoverPaths() ([]Path, error) {
	paths := append([]Path(nil), c.Paths...)
	if !c.AutoDiscoverPaths {
		return enabledPaths(paths), nil
	}
	existing := make(map[string]bool)
	tunnelPrefix, _ := netip.ParsePrefix(c.TunnelAddress)
	for _, path := range paths {
		existing[path.LocalAddress] = true
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	defaults := defaultPathInterfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Name == c.TunnelName {
			continue
		}
		if looksVirtualInterface(iface.Name, iface.Flags) {
			continue
		}
		if len(defaults) > 0 && !defaults[iface.Name] {
			// Windows route discovery keys defaults by interface address.
			hasDefaultAddress := false
			addresses, _ := iface.Addrs()
			for _, address := range addresses {
				prefix, parseErr := netip.ParsePrefix(address.String())
				if parseErr == nil && defaults["ip:"+prefix.Addr().String()] {
					hasDefaultAddress = true
					break
				}
			}
			if !hasDefaultAddress {
				continue
			}
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addrs {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
				continue
			}
			if tunnelPrefix.IsValid() && prefix.Addr() == tunnelPrefix.Addr() {
				continue
			}
			ip := prefix.Addr().String()
			if existing[ip] {
				continue
			}
			paths = append(paths, Path{
				Name:         iface.Name + "-" + strings.ReplaceAll(ip, ".", "_"),
				LocalAddress: ip,
				Interface:    iface.Name,
				Weight:       1,
			})
			existing[ip] = true
		}
	}
	return enabledPaths(paths), nil
}

func (c Client) EffectiveRoutes() []string {
	if c.TrafficMode == "all" {
		return []string{"0.0.0.0/1", "128.0.0.0/1"}
	}
	return append([]string(nil), c.Routes...)
}

func looksVirtualInterface(name string, flags net.Flags) bool {
	if flags&net.FlagPointToPoint != 0 {
		return true
	}
	name = strings.ToLower(name)
	for _, prefix := range []string{"br-", "docker", "veth", "virbr", "vmnet", "vboxnet", "zt", "tailscale", "tun", "tap", "wg", "linkforge", "vethernet"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func enabledPaths(paths []Path) []Path {
	result := paths[:0]
	for _, path := range paths {
		if path.IsEnabled() {
			result = append(result, path)
		}
	}
	return result
}
