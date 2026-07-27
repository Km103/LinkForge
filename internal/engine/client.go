package engine

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Km103/LinkForge/internal/config"
	"github.com/Km103/LinkForge/internal/metrics"
	"github.com/Km103/LinkForge/internal/netbind"
	"github.com/Km103/LinkForge/internal/protocol"
	"github.com/Km103/LinkForge/internal/reorder"
	"github.com/Km103/LinkForge/internal/scheduler"
	"github.com/Km103/LinkForge/internal/tun"
)

type Client struct {
	config    config.Client
	logger    *slog.Logger
	metrics   *metrics.Registry
	tun       tun.Device
	key       []byte
	clientID  [16]byte
	tunnelIP  netip.Addr
	remote    *net.UDPAddr
	scheduler *scheduler.Scheduler
	reorder   *reorder.Buffer
	dataSeq   atomic.Uint64
	sessionID atomic.Uint64
	rejoining atomic.Bool

	mu            sync.RWMutex
	deliverMu     sync.Mutex
	instanceMu    sync.RWMutex
	instanceNonce [16]byte
	paths         []*clientPath
}

type clientPath struct {
	config         config.Path
	conn           *net.UDPConn
	aead           cipher.AEAD
	sessionID      uint64
	pathID         uint32
	sequence       atomic.Uint64
	replay         protocol.ReplayWindow
	lastSeenNanos  atomic.Int64
	rttNanos       atomic.Int64
	healthy        atomic.Bool
	healthTimeout  time.Duration
	metric         *metrics.Path
	logger         *slog.Logger
	writeErrorOnce sync.Once
	reconnecting   atomic.Bool
}

type DiagnosticResult struct {
	Duration      time.Duration
	SentBytes     uint64
	ReceivedBytes uint64
	Paths         []PathDiagnostic
}

type PathDiagnostic struct {
	Name          string
	LocalAddress  string
	RTT           time.Duration
	SentBytes     uint64
	ReceivedBytes uint64
	Healthy       bool
}

func NewClient(c config.Client, device tun.Device, logger *slog.Logger, registry *metrics.Registry) (*Client, error) {
	key, err := c.Key()
	if err != nil {
		return nil, err
	}
	clientID, err := protocol.ParseClientID(c.ClientID)
	if err != nil {
		return nil, err
	}
	prefix, err := netip.ParsePrefix(c.TunnelAddress)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", c.Server)
	if err != nil {
		return nil, err
	}
	if registry == nil {
		registry = metrics.New("client")
	}
	var instanceNonce [16]byte
	if _, err := rand.Read(instanceNonce[:]); err != nil {
		return nil, fmt.Errorf("create client instance nonce: %w", err)
	}
	return &Client{
		config:        c,
		logger:        logger,
		metrics:       registry,
		tun:           device,
		key:           key,
		clientID:      clientID,
		tunnelIP:      prefix.Addr(),
		remote:        remote,
		scheduler:     scheduler.New(),
		reorder:       reorder.New(c.ReorderWindow, c.ReorderDelay.Value(80*time.Millisecond)),
		instanceNonce: instanceNonce,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	if c.tun == nil {
		return errors.New("client requires a TUN device")
	}
	if err := c.connect(ctx); err != nil {
		return err
	}
	c.metrics.SetReady(true)
	defer c.metrics.SetReady(false)
	defer c.close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 1)

	c.startReceivers(runCtx, c.snapshotPaths())
	go c.healthLoop(runCtx)
	go c.reorderLoop(runCtx)
	go c.statsLoop(runCtx)
	go func() { errCh <- c.tunLoop(runCtx) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if ctx.Err() != nil || isClosed(err) {
			return nil
		}
		return err
	}
}

func (c *Client) connect(ctx context.Context) error {
	paths, err := c.config.DiscoverPaths()
	if err != nil {
		return fmt.Errorf("discover paths: %w", err)
	}
	if len(paths) == 0 {
		return errors.New("no enabled network paths discovered")
	}

	type result struct {
		path *clientPath
		err  error
	}
	results := make(chan result, len(paths))
	var wg sync.WaitGroup
	for _, pathConfig := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			path, err := c.connectPath(ctx, pathConfig)
			results <- result{path: path, err: err}
		}()
	}
	wg.Wait()
	close(results)

	var connected []*clientPath
	for result := range results {
		if result.err != nil {
			c.logger.Warn("path connection failed",
				"path", pathName(result.path, result.err),
				"error", result.err,
			)
			continue
		}
		connected = append(connected, result.path)
	}
	if len(connected) == 0 {
		return errors.New("all paths failed to authenticate with the relay")
	}
	sessionID := connected[0].sessionID
	usable := connected[:0]
	for _, path := range connected {
		if path.sessionID != sessionID {
			path.logger.Warn("path joined a different relay session; closing it", "expected_session_id", sessionID, "actual_session_id", path.sessionID)
			_ = path.conn.Close()
			continue
		}
		usable = append(usable, path)
	}
	connected = usable
	if len(connected) == 0 {
		return errors.New("relay returned inconsistent sessions for all paths")
	}
	c.sessionID.Store(sessionID)
	c.mu.Lock()
	c.paths = connected
	c.mu.Unlock()
	c.logger.Info("multipath session established",
		"server", c.remote,
		"connected_paths", len(connected),
		"client_id", protocol.ClientIDString(c.clientID),
	)
	return nil
}

func pathName(path *clientPath, err error) string {
	if path != nil {
		return path.config.Name
	}
	type named interface{ PathName() string }
	if value, ok := err.(named); ok {
		return value.PathName()
	}
	return "unknown"
}

type pathError struct {
	name string
	err  error
}

func (e pathError) Error() string    { return e.name + ": " + e.err.Error() }
func (e pathError) Unwrap() error    { return e.err }
func (e pathError) PathName() string { return e.name }

func (c *Client) connectPath(ctx context.Context, pathConfig config.Path) (*clientPath, error) {
	localIP, err := resolveLocalIP(pathConfig)
	if err != nil {
		return nil, pathError{pathConfig.Name, err}
	}
	local := &net.UDPAddr{IP: localIP, Port: 0}
	conn, err := netbind.DialUDP(ctx, local, c.remote, pathConfig.Interface)
	if err != nil {
		return nil, pathError{pathConfig.Name, fmt.Errorf("open UDP socket: %w", err)}
	}
	tuneUDPSocket(conn, c.logger.With("path", pathConfig.Name))
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()

	hello, err := protocol.NewHello(c.clientID, c.currentInstanceNonce(), pathConfig.Name, pathConfig.Weight)
	if err != nil {
		return nil, pathError{pathConfig.Name, err}
	}
	payload, err := hello.Marshal(c.key)
	if err != nil {
		return nil, pathError{pathConfig.Name, err}
	}
	packet, _ := protocol.MarshalPlain(protocol.Header{Type: protocol.TypeHello}, payload)
	timeout := c.config.HandshakeTimeout.Value(8 * time.Second)
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, protocol.MaxDatagram)
	var header protocol.Header
	var welcome protocol.Welcome

	for time.Now().Before(deadline) {
		if err := conn.SetDeadline(minTime(deadline, time.Now().Add(750*time.Millisecond))); err != nil {
			return nil, pathError{pathConfig.Name, err}
		}
		if _, err := conn.Write(packet); err != nil {
			return nil, pathError{pathConfig.Name, fmt.Errorf("send hello: %w", err)}
		}
		count, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return nil, pathError{pathConfig.Name, fmt.Errorf("read welcome: %w", err)}
		}
		header, err = protocol.ParseHeader(buffer[:count])
		if err != nil || header.Type != protocol.TypeWelcome || header.PathID == 0 || header.SessionID == 0 {
			continue
		}
		responsePayload, err := protocol.PlainPayload(buffer[:count])
		if err != nil {
			continue
		}
		welcome, err = protocol.ParseWelcome(responsePayload, c.key, header, hello.Nonce, time.Now())
		if err == nil {
			break
		}
	}
	if welcome.ServerNonce == ([16]byte{}) {
		return nil, pathError{pathConfig.Name, fmt.Errorf("handshake timed out after %s", timeout)}
	}
	_ = conn.SetDeadline(time.Time{})
	aead, err := protocol.NewAEAD(c.key, hello.Nonce, welcome.ServerNonce, header.SessionID, header.PathID)
	if err != nil {
		return nil, pathError{pathConfig.Name, err}
	}
	metric := c.metrics.Path(pathConfig.Name)
	metric.Healthy.Store(true)
	path := &clientPath{
		config:        pathConfig,
		conn:          conn,
		aead:          aead,
		sessionID:     header.SessionID,
		pathID:        header.PathID,
		healthTimeout: 4 * c.config.HealthInterval.Value(config.DefaultHealthInterval),
		metric:        metric,
		logger:        c.logger.With("path", pathConfig.Name, "path_id", header.PathID),
	}
	path.healthy.Store(true)
	path.lastSeenNanos.Store(time.Now().UnixNano())
	closeOnError = false
	c.logger.Info("path authenticated",
		"path", pathConfig.Name,
		"local_address", conn.LocalAddr(),
		"server", c.remote,
		"session_id", header.SessionID,
		"path_id", header.PathID,
		"weight", pathConfig.Weight,
	)
	return path, nil
}

func resolveLocalIP(path config.Path) (net.IP, error) {
	if path.LocalAddress != "" {
		ip := net.ParseIP(path.LocalAddress)
		if ip == nil {
			return nil, fmt.Errorf("invalid local address %q", path.LocalAddress)
		}
		return ip, nil
	}
	if path.Interface != "" {
		iface, err := net.InterfaceByName(path.Interface)
		if err != nil {
			return nil, err
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
				return net.IP(prefix.Addr().AsSlice()), nil
			}
		}
		return nil, fmt.Errorf("interface %s has no IPv4 address", path.Interface)
	}
	// An unspecified address delegates source selection to the OS.
	return net.IPv4zero, nil
}

func (c *Client) tunLoop(ctx context.Context) error {
	for {
		packet, err := c.tun.ReadPacket()
		if err != nil {
			if ctx.Err() != nil || isClosed(err) {
				return nil
			}
			c.metrics.TUNReadErrors.Add(1)
			return fmt.Errorf("read TUN: %w", err)
		}
		source, err := protocol.SourceIP(packet)
		if err != nil || source != c.tunnelIP {
			c.metrics.InvalidPackets.Add(1)
			c.logger.Debug("dropped spoofed or malformed TUN packet", "source", source, "error", err)
			continue
		}
		path := c.nextPath()
		if path == nil {
			c.metrics.NoPathDrops.Add(1)
			continue
		}
		payload, err := protocol.MarshalData(c.dataSeq.Add(1), packet)
		if err != nil {
			c.metrics.InvalidPackets.Add(1)
			continue
		}
		if err := path.send(protocol.TypeData, payload); err != nil {
			path.recordWriteError(err)
			continue
		}
		c.metrics.SentPackets.Add(1)
		c.metrics.SentBytes.Add(uint64(len(packet)))
	}
}

func (c *Client) nextPath() *clientPath {
	paths := c.snapshotPaths()
	candidates := make([]scheduler.Candidate, len(paths))
	for i := range paths {
		candidates[i] = paths[i]
	}
	selected := c.scheduler.Next(candidates, time.Now())
	if selected == nil {
		return nil
	}
	return selected.(*clientPath)
}

func (c *Client) handlePacket(path *clientPath, packetType protocol.Type, payload []byte) {
	switch packetType {
	case protocol.TypeData:
		sequence, ipPacket, err := protocol.ParseData(payload)
		if err != nil {
			c.metrics.InvalidPackets.Add(1)
			return
		}
		destination, err := protocol.DestinationIP(ipPacket)
		if err != nil || destination != c.tunnelIP {
			c.metrics.InvalidPackets.Add(1)
			path.logger.Debug("dropped packet with unexpected tunnel destination", "destination", destination, "error", err)
			return
		}
		if c.tun == nil {
			path.logger.Debug("ignored tunnel data while running diagnostics")
			return
		}
		c.deliverMu.Lock()
		c.deliver(c.reorder.Push(sequence, ipPacket, time.Now()), path.logger)
		c.deliverMu.Unlock()
	case protocol.TypePong:
		if len(payload) != 8 {
			c.metrics.InvalidPackets.Add(1)
			return
		}
		sentAt := int64(binary.BigEndian.Uint64(payload))
		rtt := time.Since(time.Unix(0, sentAt))
		if rtt > 0 && rtt < time.Minute {
			path.updateRTT(rtt)
		}
	case protocol.TypeProbeReply:
		// Metrics are updated in receiveLoop; diagnostics consume the counters.
	case protocol.TypeClose:
		path.markUnhealthy("relay closed path")
	default:
		c.metrics.InvalidPackets.Add(1)
	}
}

func (c *Client) reorderLoop(ctx context.Context) {
	interval := c.reorder.MaxDelay() / 4
	if interval > 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.deliverMu.Lock()
			c.deliver(c.reorder.FlushExpired(now), c.logger)
			c.deliverMu.Unlock()
		}
	}
}

func (c *Client) deliver(result reorder.Result, logger *slog.Logger) {
	if result.Skipped > 0 {
		c.metrics.ReorderSkips.Add(result.Skipped)
		logger.Debug("reorder deadline skipped missing packets", "count", result.Skipped)
	}
	if c.tun == nil {
		return
	}
	for _, packet := range result.Packets {
		if err := c.tun.WritePacket(packet); err != nil {
			c.metrics.TUNWriteErrors.Add(1)
			logger.Warn("write to TUN failed", "error", err)
			continue
		}
		c.metrics.ReceivedPackets.Add(1)
		c.metrics.ReceivedBytes.Add(uint64(len(packet)))
	}
}

func (c *Client) healthLoop(ctx context.Context) {
	interval := c.config.HealthInterval.Value(config.DefaultHealthInterval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			var timestamp [8]byte
			binary.BigEndian.PutUint64(timestamp[:], uint64(now.UnixNano()))
			paths := c.snapshotPaths()
			if len(paths) == 0 {
				go c.rejoinAll(ctx)
				continue
			}
			for _, path := range paths {
				if err := path.send(protocol.TypePing, timestamp[:]); err != nil {
					path.recordWriteError(err)
				}
				path.refreshHealth(now)
				if !path.IsHealthy(now) {
					go c.reconnectPath(ctx, path)
				}
			}
		}
	}
}

func (c *Client) startReceivers(ctx context.Context, paths []*clientPath) {
	for _, path := range paths {
		go path.receiveLoop(ctx, c.handlePacket)
	}
}

func (c *Client) reconnectPath(ctx context.Context, old *clientPath) {
	if !old.reconnecting.CompareAndSwap(false, true) {
		return
	}
	defer old.reconnecting.Store(false)
	if ctx.Err() != nil {
		return
	}
	old.logger.Info("attempting path re-handshake")
	replacement, err := c.connectPath(ctx, old.config)
	if err != nil {
		old.logger.Warn("path re-handshake failed", "error", err)
		return
	}
	if ctx.Err() != nil {
		_ = replacement.conn.Close()
		return
	}
	if replacement.sessionID != c.sessionID.Load() {
		replacement.logger.Info("relay session changed; rejoining every path")
		_ = replacement.conn.Close()
		go c.rejoinAll(ctx)
		return
	}
	c.mu.Lock()
	replaced := false
	for index, current := range c.paths {
		if current == old {
			c.paths[index] = replacement
			replaced = true
			break
		}
	}
	c.mu.Unlock()
	if !replaced {
		_ = replacement.conn.Close()
		return
	}
	_ = old.conn.Close()
	c.startReceivers(ctx, []*clientPath{replacement})
	replacement.logger.Info("path rejoined")
}

func (c *Client) rejoinAll(ctx context.Context) {
	if !c.rejoining.CompareAndSwap(false, true) {
		return
	}
	defer c.rejoining.Store(false)
	if ctx.Err() != nil {
		return
	}
	oldPaths := c.snapshotPaths()
	for _, path := range oldPaths {
		_ = path.conn.Close()
	}
	c.mu.Lock()
	c.paths = nil
	c.mu.Unlock()
	c.deliverMu.Lock()
	if err := c.rotateInstanceNonce(); err != nil {
		c.deliverMu.Unlock()
		c.logger.Error("could not create a new relay session identity", "error", err)
		return
	}
	c.reorder.Reset()
	c.dataSeq.Store(0)
	c.sessionID.Store(0)
	c.deliverMu.Unlock()
	c.logger.Info("rejoining relay session", "paths", len(oldPaths))
	if err := c.connect(ctx); err != nil {
		c.logger.Warn("relay session rejoin failed", "error", err)
		return
	}
	c.startReceivers(ctx, c.snapshotPaths())
	c.logger.Info("relay session rejoined", "session_id", c.sessionID.Load())
}

func (c *Client) currentInstanceNonce() [16]byte {
	c.instanceMu.RLock()
	defer c.instanceMu.RUnlock()
	return c.instanceNonce
}

func (c *Client) rotateInstanceNonce() error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	c.instanceMu.Lock()
	c.instanceNonce = nonce
	c.instanceMu.Unlock()
	return nil
}

func (c *Client) statsLoop(ctx context.Context) {
	interval := c.config.StatsInterval.Value(15 * time.Second)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			healthy := 0
			for _, path := range c.snapshotPaths() {
				if path.IsHealthy(time.Now()) {
					healthy++
				}
				c.logger.Info("path statistics",
					"path", path.config.Name,
					"healthy", path.IsHealthy(time.Now()),
					"rtt", path.RTT(),
					"sent_bytes", path.metric.SentBytes.Load(),
					"received_bytes", path.metric.ReceivedBytes.Load(),
					"write_errors", path.metric.WriteErrors.Load(),
				)
			}
			c.logger.Info("tunnel statistics",
				"healthy_paths", healthy,
				"sent_bytes", c.metrics.SentBytes.Load(),
				"received_bytes", c.metrics.ReceivedBytes.Load(),
				"no_path_drops", c.metrics.NoPathDrops.Load(),
				"reorder_skips", c.metrics.ReorderSkips.Load(),
			)
		}
	}
}

func (c *Client) snapshotPaths() []*clientPath {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]*clientPath(nil), c.paths...)
}

func (c *Client) close() {
	for _, path := range c.snapshotPaths() {
		_ = path.send(protocol.TypeClose, nil)
		_ = path.conn.Close()
	}
	if c.tun != nil {
		_ = c.tun.Close()
	}
}

func (p *clientPath) PathName() string { return p.config.Name }

func (p *clientPath) ConfiguredWeight() float64 { return p.config.Weight }

func (p *clientPath) RTT() time.Duration {
	return time.Duration(p.rttNanos.Load())
}

func (p *clientPath) IsHealthy(now time.Time) bool {
	if !p.healthy.Load() {
		return false
	}
	lastSeen := time.Unix(0, p.lastSeenNanos.Load())
	return now.Sub(lastSeen) <= p.healthTimeout
}

func (p *clientPath) send(packetType protocol.Type, payload []byte) error {
	sequence := p.sequence.Add(1)
	header := protocol.Header{
		Type:      packetType,
		SessionID: p.sessionID,
		PathID:    p.pathID,
		Sequence:  sequence,
	}
	packet, err := protocol.Seal(p.aead, header, protocol.ClientToServer, payload)
	if err != nil {
		return err
	}
	if _, err := p.conn.Write(packet); err != nil {
		return err
	}
	p.metric.SentPackets.Add(1)
	p.metric.SentBytes.Add(uint64(len(payload)))
	return nil
}

func (p *clientPath) receiveLoop(ctx context.Context, callback func(*clientPath, protocol.Type, []byte)) {
	buffer := make([]byte, protocol.MaxDatagram)
	for {
		count, err := p.conn.Read(buffer)
		if err != nil {
			if ctx.Err() != nil || isClosed(err) {
				return
			}
			p.markUnhealthy("receive failed")
			p.logger.Warn("path receive failed; retrying", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		header, err := protocol.ParseHeader(buffer[:count])
		if err != nil || header.SessionID != p.sessionID || header.PathID != p.pathID || protocol.IsHandshake(header.Type) {
			p.metric.AuthFailures.Add(1)
			continue
		}
		payload, err := protocol.Open(p.aead, header, protocol.ServerToClient, buffer[:count])
		if err != nil {
			p.metric.AuthFailures.Add(1)
			continue
		}
		if !p.replay.Accept(header.Sequence) {
			p.metric.ReplayDrops.Add(1)
			continue
		}
		p.lastSeenNanos.Store(time.Now().UnixNano())
		if !p.healthy.Swap(true) {
			p.metric.Healthy.Store(true)
			p.logger.Info("path recovered")
		}
		p.metric.ReceivedPackets.Add(1)
		p.metric.ReceivedBytes.Add(uint64(len(payload)))
		callback(p, header.Type, payload)
	}
}

func (p *clientPath) updateRTT(sample time.Duration) {
	const smoothing = 8
	old := p.rttNanos.Load()
	value := int64(sample)
	if old > 0 {
		value = (old*(smoothing-1) + value) / smoothing
	}
	p.rttNanos.Store(value)
	p.metric.RTTNanos.Store(value)
}

func (p *clientPath) refreshHealth(now time.Time) {
	healthy := now.Sub(time.Unix(0, p.lastSeenNanos.Load())) <= p.healthTimeout
	if p.healthy.Swap(healthy) != healthy {
		p.metric.Healthy.Store(healthy)
		if healthy {
			p.logger.Info("path recovered")
		} else {
			p.logger.Warn("path unhealthy", "last_seen", time.Unix(0, p.lastSeenNanos.Load()))
		}
	}
}

func (p *clientPath) markUnhealthy(reason string) {
	if p.healthy.Swap(false) {
		p.metric.Healthy.Store(false)
		p.logger.Warn("path unhealthy", "reason", reason)
	}
}

func (p *clientPath) recordWriteError(err error) {
	p.metric.WriteErrors.Add(1)
	p.markUnhealthy("write failed")
	p.writeErrorOnce.Do(func() {
		p.logger.Warn("path write failed", "error", err)
	})
}

func (c *Client) Diagnose(ctx context.Context, duration time.Duration, payloadSize int) (DiagnosticResult, error) {
	if duration <= 0 {
		duration = 5 * time.Second
	}
	if payloadSize < 64 || payloadSize > 1200 {
		return DiagnosticResult{}, errors.New("diagnostic payload size must be between 64 and 1200")
	}
	if err := c.connect(ctx); err != nil {
		return DiagnosticResult{}, err
	}
	defer c.close()
	paths := c.snapshotPaths()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, path := range paths {
		go path.receiveLoop(runCtx, c.handlePacket)
	}
	go c.healthLoop(runCtx)
	// Establish an RTT sample before saturating the paths.
	select {
	case <-time.After(1100 * time.Millisecond):
	case <-ctx.Done():
		return DiagnosticResult{}, ctx.Err()
	}

	startSent := make(map[*clientPath]uint64, len(paths))
	startReceived := make(map[*clientPath]uint64, len(paths))
	for _, path := range paths {
		startSent[path] = path.metric.SentBytes.Load()
		startReceived[path] = path.metric.ReceivedBytes.Load()
	}
	testCtx, stopTest := context.WithTimeout(runCtx, duration)
	defer stopTest()
	var wg sync.WaitGroup
	for _, path := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := make([]byte, payloadSize)
			for testCtx.Err() == nil {
				binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().UnixNano()))
				if err := path.send(protocol.TypeProbe, payload); err != nil {
					path.recordWriteError(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	// Let in-flight echo packets arrive.
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
	}

	result := DiagnosticResult{Duration: duration}
	for _, path := range paths {
		sent := path.metric.SentBytes.Load() - startSent[path]
		received := path.metric.ReceivedBytes.Load() - startReceived[path]
		result.SentBytes += sent
		result.ReceivedBytes += received
		local := ""
		if path.conn.LocalAddr() != nil {
			local = path.conn.LocalAddr().String()
		}
		result.Paths = append(result.Paths, PathDiagnostic{
			Name:          path.config.Name,
			LocalAddress:  local,
			RTT:           path.RTT(),
			SentBytes:     sent,
			ReceivedBytes: received,
			Healthy:       path.IsHealthy(time.Now()),
		})
	}
	return result, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}
