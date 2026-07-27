package engine

import (
	"bytes"
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
	"github.com/Km103/LinkForge/internal/protocol"
	"github.com/Km103/LinkForge/internal/reorder"
	"github.com/Km103/LinkForge/internal/scheduler"
	"github.com/Km103/LinkForge/internal/tun"
)

type Server struct {
	config       config.Server
	logger       *slog.Logger
	metrics      *metrics.Registry
	tun          tun.Device
	conn         *net.UDPConn
	credentialMu sync.RWMutex
	credentials  map[string]serverCredential
	hookMu       sync.RWMutex
	clientSeen   func(string)

	mu              sync.RWMutex
	sessions        map[uint64]*serverSession
	sessionByClient map[string]*serverSession
	sessionByIP     map[netip.Addr]*serverSession
}

type serverCredential struct {
	name     string
	clientID [16]byte
	key      []byte
	tunnelIP netip.Addr
}

type serverSession struct {
	id            uint64
	credential    serverCredential
	instanceNonce [16]byte
	legacy        bool
	logger        *slog.Logger
	scheduler     *scheduler.Scheduler
	createdAt     time.Time
	lastSeen      atomic.Int64
	nextPathID    atomic.Uint32
	dataSeq       atomic.Uint64
	reorder       *reorder.Buffer
	deliverMu     sync.Mutex
	mu            sync.RWMutex
	closing       bool
	paths         map[uint32]*serverPath
}

type serverPath struct {
	id             uint32
	sessionID      uint64
	name           string
	clientNonce    [16]byte
	serverNonce    [16]byte
	welcomePacket  []byte
	aead           cipher.AEAD
	sequence       atomic.Uint64
	replay         protocol.ReplayWindow
	lastSeenNanos  atomic.Int64
	rttNanos       atomic.Int64
	healthy        atomic.Bool
	metric         *metrics.Path
	logger         *slog.Logger
	conn           *net.UDPConn
	healthTimeout  time.Duration
	weight         float64
	remoteMu       sync.RWMutex
	remote         *net.UDPAddr
	writeErrorOnce sync.Once
}

func NewServer(c config.Server, device tun.Device, logger *slog.Logger, registry *metrics.Registry) (*Server, error) {
	if device == nil {
		return nil, errors.New("server requires a TUN device")
	}
	if registry == nil {
		registry = metrics.New("server")
	}
	server := &Server{
		config:          c,
		logger:          logger,
		metrics:         registry,
		tun:             device,
		credentials:     make(map[string]serverCredential, len(c.Clients)),
		sessions:        make(map[uint64]*serverSession),
		sessionByClient: make(map[string]*serverSession),
		sessionByIP:     make(map[netip.Addr]*serverSession),
	}
	for _, configured := range c.Clients {
		if err := server.AuthorizeClient(configured); err != nil {
			return nil, err
		}
	}
	return server, nil
}

func (s *Server) AuthorizeClient(configured config.ClientCredential) error {
	id, err := protocol.ParseClientID(configured.ClientID)
	if err != nil {
		return err
	}
	key, err := configured.Key()
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(configured.TunnelAddress)
	if err != nil || !prefix.Addr().Is4() {
		return errors.New("managed client tunnel address must be IPv4")
	}
	serverPrefix, err := netip.ParsePrefix(s.config.TunnelAddress)
	if err != nil {
		return err
	}
	if !serverPrefix.Contains(prefix.Addr()) || prefix.Addr() == serverPrefix.Addr() {
		return fmt.Errorf("managed client tunnel IP %s is outside %s", prefix.Addr(), serverPrefix)
	}
	idText := protocol.ClientIDString(id)
	credential := serverCredential{
		name:     configured.Name,
		clientID: id,
		key:      append([]byte(nil), key...),
		tunnelIP: prefix.Addr(),
	}
	s.credentialMu.Lock()
	for otherID, existing := range s.credentials {
		if otherID != idText && existing.tunnelIP == credential.tunnelIP {
			s.credentialMu.Unlock()
			return fmt.Errorf("managed client tunnel IP %s is already assigned", credential.tunnelIP)
		}
		if otherID != idText && bytes.Equal(existing.key, credential.key) {
			s.credentialMu.Unlock()
			return errors.New("managed client key is already assigned")
		}
	}
	previous, replacing := s.credentials[idText]
	s.credentials[idText] = credential
	s.credentialMu.Unlock()
	if replacing && (!bytes.Equal(previous.key, credential.key) || previous.tunnelIP != credential.tunnelIP) {
		s.terminateClientSession(idText, "credential replaced")
	}
	return nil
}

func (s *Server) RevokeClient(clientID string) {
	id, err := protocol.ParseClientID(clientID)
	if err != nil {
		return
	}
	idText := protocol.ClientIDString(id)
	s.credentialMu.Lock()
	delete(s.credentials, idText)
	s.credentialMu.Unlock()
	s.terminateClientSession(idText, "credential revoked")
}

func (s *Server) SetClientSeenHook(hook func(string)) {
	s.hookMu.Lock()
	s.clientSeen = hook
	s.hookMu.Unlock()
}

func (s *Server) credential(clientID string) (serverCredential, bool) {
	s.credentialMu.RLock()
	defer s.credentialMu.RUnlock()
	credential, ok := s.credentials[clientID]
	return credential, ok
}

func (s *Server) credentialCount() int {
	s.credentialMu.RLock()
	defer s.credentialMu.RUnlock()
	return len(s.credentials)
}

func (s *Server) Run(ctx context.Context) error {
	listen, err := net.ResolveUDPAddr("udp", s.config.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	tuneUDPSocket(conn, s.logger)
	s.conn = conn
	s.metrics.SetReady(true)
	defer s.metrics.SetReady(false)
	defer conn.Close()
	defer s.tun.Close()

	s.logger.Info("relay listening",
		"address", conn.LocalAddr(),
		"tunnel", s.tun.Name(),
		"authorized_clients", s.credentialCount(),
	)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 3)
	go func() { errCh <- s.receiveLoop(runCtx) }()
	go func() { errCh <- s.tunLoop(runCtx) }()
	go s.janitorLoop(runCtx)
	go s.reorderLoop(runCtx)
	go s.statsLoop(runCtx)

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

func (s *Server) receiveLoop(ctx context.Context) error {
	buffer := make([]byte, protocol.MaxDatagram)
	for {
		count, remote, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || isClosed(err) {
				return nil
			}
			return fmt.Errorf("relay UDP read: %w", err)
		}
		packet := append([]byte(nil), buffer[:count]...)
		header, err := protocol.ParseHeader(packet)
		if err != nil {
			s.metrics.InvalidPackets.Add(1)
			continue
		}
		if header.Type == protocol.TypeHello {
			s.handleHello(remote, header, packet)
			continue
		}
		s.handleEncrypted(remote, header, packet)
	}
}

func (s *Server) handleHello(remote *net.UDPAddr, header protocol.Header, packet []byte) {
	payload, err := protocol.PlainPayload(packet)
	if err != nil || len(payload) < 16 {
		s.metrics.InvalidPackets.Add(1)
		return
	}
	var clientID [16]byte
	copy(clientID[:], payload[:16])
	idText := protocol.ClientIDString(clientID)
	credential, ok := s.credential(idText)
	if !ok {
		s.metrics.AuthFailures.Add(1)
		s.logger.Warn("hello from unknown client", "remote", remote, "client_id", idText)
		return
	}
	hello, err := protocol.ParseHello(payload, credential.key, time.Now())
	if err != nil {
		s.metrics.AuthFailures.Add(1)
		s.logger.Warn("client hello rejected", "remote", remote, "client", credential.name, "error", err)
		return
	}
	session, err := s.getOrCreateSession(credential, hello)
	if err != nil {
		s.logger.Error("could not create client session", "client", credential.name, "error", err)
		return
	}
	if existing := session.pathForNonce(hello.Nonce); existing != nil {
		if !sameUDPAddr(existing.remoteAddress(), remote) {
			existing.logger.Warn("replayed hello from a different address rejected", "remote", remote)
			return
		}
		if _, err := s.conn.WriteToUDP(existing.welcomePacket, remote); err != nil {
			existing.recordWriteError(err)
		} else {
			existing.healthy.Store(true)
			existing.metric.Healthy.Store(true)
		}
		return
	}
	pathID := session.nextPathID.Add(1)
	if pathID == 0 || pathID >= 1<<31 {
		s.logger.Error("path ID space exhausted", "client", credential.name)
		return
	}
	welcome, err := protocol.NewWelcome(hello.Nonce)
	if err != nil {
		s.logger.Error("create welcome", "error", err)
		return
	}
	welcomeHeader := protocol.Header{
		Type:      protocol.TypeWelcome,
		SessionID: session.id,
		PathID:    pathID,
	}
	welcomePayload := welcome.Marshal(credential.key, welcomeHeader)
	welcomePacket, _ := protocol.MarshalPlain(welcomeHeader, welcomePayload)
	aead, err := protocol.NewAEAD(credential.key, hello.Nonce, welcome.ServerNonce, session.id, pathID)
	if err != nil {
		s.logger.Error("derive path key", "error", err)
		return
	}
	metricName := credential.name + "/" + hello.PathName
	path := &serverPath{
		id:            pathID,
		sessionID:     session.id,
		name:          hello.PathName,
		clientNonce:   hello.Nonce,
		serverNonce:   welcome.ServerNonce,
		welcomePacket: welcomePacket,
		aead:          aead,
		conn:          s.conn,
		remote:        cloneUDPAddr(remote),
		healthTimeout: 10 * time.Second,
		weight:        float64(hello.Weight) / 100,
		metric:        s.metrics.Path(metricName),
		logger:        session.logger.With("path", hello.PathName, "path_id", pathID),
	}
	path.healthy.Store(true)
	path.metric.Healthy.Store(true)
	path.lastSeenNanos.Store(time.Now().UnixNano())
	if !session.addPath(path) {
		path.healthy.Store(false)
		path.metric.Healthy.Store(false)
		return
	}
	session.touch()
	if _, err := s.conn.WriteToUDP(welcomePacket, remote); err != nil {
		path.recordWriteError(err)
		if session.removePath(path) {
			s.terminateSessionIfCurrent(session, "initial welcome failed")
		}
		return
	}
	path.logger.Info("path registered", "remote", remote)
}

func (s *Server) getOrCreateSession(credential serverCredential, hello protocol.Hello) (*serverSession, error) {
	idText := protocol.ClientIDString(credential.clientID)
	s.credentialMu.RLock()
	current, authorized := s.credentials[idText]
	if !authorized || !bytes.Equal(current.key, credential.key) || current.tunnelIP != credential.tunnelIP {
		s.credentialMu.RUnlock()
		return nil, errors.New("client credential changed during handshake")
	}
	defer s.credentialMu.RUnlock()

	s.mu.Lock()
	existing := s.sessionByClient[idText]
	if existing != nil && existing.accepts(hello) {
		s.mu.Unlock()
		return existing, nil
	}
	sessionID, err := randomUint64()
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	for sessionID == 0 || s.sessions[sessionID] != nil {
		sessionID, err = randomUint64()
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
	}
	var replacedPaths []*serverPath
	if existing != nil {
		replacedPaths = existing.markClosing()
		s.detachSessionLocked(existing)
	}
	now := time.Now()
	session := &serverSession{
		id:            sessionID,
		credential:    credential,
		instanceNonce: hello.InstanceNonce,
		legacy:        hello.WireVersion < 2,
		logger: s.logger.With(
			"session_id", sessionID,
			"client", credential.name,
			"client_id", idText,
			"tunnel_ip", credential.tunnelIP,
		),
		scheduler: scheduler.New(),
		createdAt: now,
		paths:     make(map[uint32]*serverPath),
		reorder:   reorder.New(s.config.ReorderWindow, s.config.ReorderDelay.Value(80*time.Millisecond)),
	}
	session.lastSeen.Store(now.UnixNano())
	s.sessions[sessionID] = session
	s.sessionByClient[idText] = session
	s.sessionByIP[credential.tunnelIP] = session
	s.metrics.ActiveSessions.Add(1)
	s.mu.Unlock()
	if existing != nil {
		for _, path := range replacedPaths {
			path.healthy.Store(false)
			path.metric.Healthy.Store(false)
		}
		existing.logger.Info("client session terminated", "reason", "new client process connected")
	}
	session.logger.Info("client session created")
	s.hookMu.RLock()
	hook := s.clientSeen
	s.hookMu.RUnlock()
	if hook != nil {
		go hook(idText)
	}
	return session, nil
}

func (s *Server) terminateClientSession(clientID, reason string) {
	s.mu.Lock()
	session := s.sessionByClient[clientID]
	var paths []*serverPath
	if session != nil {
		paths = session.markClosing()
		s.detachSessionLocked(session)
	}
	s.mu.Unlock()
	if session == nil {
		return
	}
	for _, path := range paths {
		path.healthy.Store(false)
		path.metric.Healthy.Store(false)
	}
	session.logger.Info("client session terminated", "reason", reason)
}

func (s *Server) terminateSessionIfCurrent(session *serverSession, reason string) {
	s.mu.Lock()
	if s.sessions[session.id] != session {
		s.mu.Unlock()
		return
	}
	paths := session.markClosing()
	s.detachSessionLocked(session)
	s.mu.Unlock()
	for _, path := range paths {
		path.healthy.Store(false)
		path.metric.Healthy.Store(false)
	}
	session.logger.Info("client session terminated", "reason", reason)
}

// detachSessionLocked removes a session from every routing index. s.mu must be held.
func (s *Server) detachSessionLocked(session *serverSession) {
	if s.sessions[session.id] != session {
		return
	}
	delete(s.sessions, session.id)
	idText := protocol.ClientIDString(session.credential.clientID)
	if s.sessionByClient[idText] == session {
		delete(s.sessionByClient, idText)
	}
	if s.sessionByIP[session.credential.tunnelIP] == session {
		delete(s.sessionByIP, session.credential.tunnelIP)
	}
	s.metrics.ActiveSessions.Add(-1)
}

func (s *Server) handleEncrypted(remote *net.UDPAddr, header protocol.Header, packet []byte) {
	s.mu.RLock()
	session := s.sessions[header.SessionID]
	s.mu.RUnlock()
	if session == nil {
		s.metrics.InvalidPackets.Add(1)
		return
	}
	path := session.path(header.PathID)
	if path == nil {
		s.metrics.InvalidPackets.Add(1)
		return
	}
	payload, err := protocol.Open(path.aead, header, protocol.ClientToServer, packet)
	if err != nil {
		s.metrics.AuthFailures.Add(1)
		path.metric.AuthFailures.Add(1)
		return
	}
	if !path.replay.Accept(header.Sequence) {
		path.metric.ReplayDrops.Add(1)
		return
	}
	path.setRemote(remote) // authenticated NAT rebinding
	now := time.Now()
	path.lastSeenNanos.Store(now.UnixNano())
	path.healthy.Store(true)
	path.metric.Healthy.Store(true)
	session.touch()
	path.metric.ReceivedPackets.Add(1)
	path.metric.ReceivedBytes.Add(uint64(len(payload)))

	switch header.Type {
	case protocol.TypeData:
		sequence, ipPacket, err := protocol.ParseData(payload)
		if err != nil {
			s.metrics.InvalidPackets.Add(1)
			return
		}
		source, err := protocol.SourceIP(ipPacket)
		if err != nil || source != session.credential.tunnelIP {
			s.metrics.InvalidPackets.Add(1)
			path.logger.Warn("spoofed tunnel packet dropped", "source", source, "error", err)
			return
		}
		session.deliverMu.Lock()
		s.deliver(session.reorder.Push(sequence, ipPacket, time.Now()), path.logger)
		session.deliverMu.Unlock()
	case protocol.TypePing:
		if len(payload) != 8 {
			s.metrics.InvalidPackets.Add(1)
			return
		}
		if err := path.send(protocol.TypePong, payload); err != nil {
			path.recordWriteError(err)
		}
	case protocol.TypeProbe:
		if err := path.send(protocol.TypeProbeReply, payload); err != nil {
			path.recordWriteError(err)
		}
	case protocol.TypeClose:
		if session.removePath(path) {
			s.terminateSessionIfCurrent(session, "last path closed")
		}
	default:
		s.metrics.InvalidPackets.Add(1)
	}
}

func (s *Server) tunLoop(ctx context.Context) error {
	for {
		packet, err := s.tun.ReadPacket()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			s.metrics.TUNReadErrors.Add(1)
			return fmt.Errorf("read relay TUN: %w", err)
		}
		destination, err := protocol.DestinationIP(packet)
		if err != nil {
			s.metrics.InvalidPackets.Add(1)
			continue
		}
		s.mu.RLock()
		session := s.sessionByIP[destination]
		s.mu.RUnlock()
		if session == nil {
			s.metrics.InvalidPackets.Add(1)
			continue
		}
		path := session.nextPath(time.Now())
		if path == nil {
			s.metrics.NoPathDrops.Add(1)
			continue
		}
		payload, err := protocol.MarshalData(session.dataSeq.Add(1), packet)
		if err != nil {
			s.metrics.InvalidPackets.Add(1)
			continue
		}
		if err := path.send(protocol.TypeData, payload); err != nil {
			path.recordWriteError(err)
			continue
		}
		s.metrics.SentPackets.Add(1)
		s.metrics.SentBytes.Add(uint64(len(packet)))
	}
}

func (s *Server) reorderLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.RLock()
			sessions := make([]*serverSession, 0, len(s.sessions))
			for _, session := range s.sessions {
				sessions = append(sessions, session)
			}
			s.mu.RUnlock()
			for _, session := range sessions {
				session.deliverMu.Lock()
				s.deliver(session.reorder.FlushExpired(now), session.logger)
				session.deliverMu.Unlock()
			}
		}
	}
}

func (s *Server) deliver(result reorder.Result, logger *slog.Logger) {
	if result.Skipped > 0 {
		s.metrics.ReorderSkips.Add(result.Skipped)
		logger.Debug("reorder deadline skipped missing packets", "count", result.Skipped)
	}
	for _, packet := range result.Packets {
		if err := s.tun.WritePacket(packet); err != nil {
			s.metrics.TUNWriteErrors.Add(1)
			logger.Warn("write to relay TUN failed", "error", err)
			continue
		}
		s.metrics.ReceivedPackets.Add(1)
		s.metrics.ReceivedBytes.Add(uint64(len(packet)))
	}
}

func (s *Server) janitorLoop(ctx context.Context) {
	interval := s.config.SessionTimeout.Value(2*time.Minute) / 4
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			timeout := s.config.SessionTimeout.Value(2 * time.Minute)
			s.mu.Lock()
			for id, session := range s.sessions {
				session.expirePaths(now)
				if now.Sub(time.Unix(0, session.lastSeen.Load())) <= timeout {
					continue
				}
				delete(s.sessions, id)
				delete(s.sessionByClient, protocol.ClientIDString(session.credential.clientID))
				delete(s.sessionByIP, session.credential.tunnelIP)
				s.metrics.ActiveSessions.Add(-1)
				session.logger.Info("client session expired", "age", now.Sub(session.createdAt))
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) statsLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.StatsInterval.Value(15 * time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			sessionCount := len(s.sessions)
			pathCount := 0
			for _, session := range s.sessions {
				pathCount += len(session.snapshotPaths())
			}
			s.mu.RUnlock()
			s.logger.Info("relay statistics",
				"sessions", sessionCount,
				"paths", pathCount,
				"sent_bytes", s.metrics.SentBytes.Load(),
				"received_bytes", s.metrics.ReceivedBytes.Load(),
				"auth_failures", s.metrics.AuthFailures.Load(),
				"invalid_packets", s.metrics.InvalidPackets.Load(),
				"reorder_skips", s.metrics.ReorderSkips.Load(),
			)
		}
	}
}

func (s *serverSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *serverSession) accepts(hello protocol.Hello) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closing {
		return false
	}
	if s.legacy || hello.WireVersion < 2 {
		return s.legacy && hello.WireVersion < 2
	}
	return bytes.Equal(s.instanceNonce[:], hello.InstanceNonce[:])
}

func (s *serverSession) addPath(path *serverPath) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.paths[path.id] = path
	return true
}

func (s *serverSession) markClosing() []*serverPath {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	paths := make([]*serverPath, 0, len(s.paths))
	for _, path := range s.paths {
		paths = append(paths, path)
	}
	return paths
}

func (s *serverSession) path(id uint32) *serverPath {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.paths[id]
}

func (s *serverSession) pathForNonce(nonce [16]byte) *serverPath {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, path := range s.paths {
		if bytes.Equal(path.clientNonce[:], nonce[:]) {
			return path
		}
	}
	return nil
}

func (s *serverSession) snapshotPaths() []*serverPath {
	s.mu.RLock()
	defer s.mu.RUnlock()
	paths := make([]*serverPath, 0, len(s.paths))
	for _, path := range s.paths {
		paths = append(paths, path)
	}
	return paths
}

func (s *serverSession) removePath(path *serverPath) bool {
	s.mu.Lock()
	if s.paths[path.id] == path {
		delete(s.paths, path.id)
	}
	empty := len(s.paths) == 0
	if empty {
		s.closing = true
	}
	s.mu.Unlock()
	path.healthy.Store(false)
	path.metric.Healthy.Store(false)
	path.logger.Info("path closed")
	return empty
}

func (s *serverSession) nextPath(now time.Time) *serverPath {
	paths := s.snapshotPaths()
	candidates := make([]scheduler.Candidate, len(paths))
	for i := range paths {
		candidates[i] = paths[i]
	}
	selected := s.scheduler.Next(candidates, now)
	if selected == nil {
		return nil
	}
	return selected.(*serverPath)
}

func (s *serverSession) expirePaths(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, path := range s.paths {
		if now.Sub(time.Unix(0, path.lastSeenNanos.Load())) > path.healthTimeout {
			path.healthy.Store(false)
			path.metric.Healthy.Store(false)
		}
		if now.Sub(time.Unix(0, path.lastSeenNanos.Load())) > time.Minute {
			delete(s.paths, id)
			path.logger.Info("stale path removed")
		}
	}
}

func (p *serverPath) PathName() string {
	return fmt.Sprintf("%s/%d", p.name, p.id)
}

func (p *serverPath) ConfiguredWeight() float64 { return p.weight }

func (p *serverPath) RTT() time.Duration { return time.Duration(p.rttNanos.Load()) }

func (p *serverPath) IsHealthy(now time.Time) bool {
	return p.healthy.Load() && now.Sub(time.Unix(0, p.lastSeenNanos.Load())) <= p.healthTimeout
}

func (p *serverPath) send(packetType protocol.Type, payload []byte) error {
	sequence := p.sequence.Add(1)
	header := protocol.Header{
		Type:      packetType,
		SessionID: p.sessionID,
		PathID:    p.id,
		Sequence:  sequence,
	}
	packet, err := protocol.Seal(p.aead, header, protocol.ServerToClient, payload)
	if err != nil {
		return err
	}
	remote := p.remoteAddress()
	if remote == nil {
		return errors.New("path has no remote address")
	}
	if _, err := p.conn.WriteToUDP(packet, remote); err != nil {
		return err
	}
	p.metric.SentPackets.Add(1)
	p.metric.SentBytes.Add(uint64(len(payload)))
	return nil
}

func (p *serverPath) setRemote(remote *net.UDPAddr) {
	p.remoteMu.Lock()
	p.remote = cloneUDPAddr(remote)
	p.remoteMu.Unlock()
}

func (p *serverPath) remoteAddress() *net.UDPAddr {
	p.remoteMu.RLock()
	defer p.remoteMu.RUnlock()
	return cloneUDPAddr(p.remote)
}

func (p *serverPath) recordWriteError(err error) {
	p.metric.WriteErrors.Add(1)
	p.healthy.Store(false)
	p.metric.Healthy.Store(false)
	p.writeErrorOnce.Do(func() {
		p.logger.Warn("path write failed", "error", err)
	})
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), address.IP...),
		Port: address.Port,
		Zone: address.Zone,
	}
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func randomUint64() (uint64, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(raw[:]), nil
}
