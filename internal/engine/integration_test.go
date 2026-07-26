package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/Km103/LinkForge/internal/config"
	"github.com/Km103/LinkForge/internal/metrics"
	"github.com/Km103/LinkForge/internal/protocol"
	"github.com/Km103/LinkForge/internal/tun"
)

const (
	testClientID = "67c42c03753048d285b2e7437299235d"
	testKey      = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
)

func TestEncryptedMultipathTunnelEndToEnd(t *testing.T) {
	address := availableUDPAddress(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	serverTUN := tun.NewMemory("server-test", 128)
	serverMetrics := metrics.New("server")
	serverConfig := config.Server{
		Listen:         address,
		TunnelAddress:  "10.77.0.1/24",
		MTU:            1280,
		ReorderWindow:  512,
		SessionTimeout: config.Duration(time.Minute),
		Clients: []config.ClientCredential{{
			Name:          "test-client",
			ClientID:      testClientID,
			PSK:           testKey,
			TunnelAddress: "10.77.0.2/24",
		}},
	}
	server, err := NewServer(serverConfig, serverTUN, logger, serverMetrics)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Run(ctx) }()
	waitReady(t, serverMetrics)

	clientTUN := tun.NewMemory("client-test", 128)
	clientMetrics := metrics.New("client")
	clientConfig := config.Client{
		Server:        address,
		ClientID:      testClientID,
		PSK:           testKey,
		TunnelAddress: "10.77.0.2/24",
		MTU:           1280,
		ReorderWindow: 512,
		Paths: []config.Path{
			{Name: "wifi", LocalAddress: "127.0.0.1", Weight: 1},
			{Name: "usb", LocalAddress: "127.0.0.1", Weight: 1},
		},
	}
	client, err := NewClient(clientConfig, clientTUN, logger, clientMetrics)
	if err != nil {
		t.Fatal(err)
	}
	clientErr := make(chan error, 1)
	go func() { clientErr <- client.Run(ctx) }()
	waitReady(t, clientMetrics)

	for sequence := byte(1); sequence <= 20; sequence++ {
		packet := ipv4Packet([4]byte{10, 77, 0, 2}, [4]byte{1, 1, 1, 1}, sequence)
		if err := clientTUN.Inject(packet); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-serverTUN.Receive():
			if !bytes.Equal(got, packet) {
				t.Fatalf("uplink packet mismatch: got %x want %x", got, packet)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for relay TUN packet")
		}
	}
	if clientMetrics.Path("wifi").SentBytes.Load() == 0 || clientMetrics.Path("usb").SentBytes.Load() == 0 {
		t.Fatal("traffic was not distributed over both configured paths")
	}

	reply := ipv4Packet([4]byte{1, 1, 1, 1}, [4]byte{10, 77, 0, 2}, 99)
	if err := serverTUN.Inject(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-clientTUN.Receive():
		if !bytes.Equal(got, reply) {
			t.Fatalf("downlink packet mismatch: got %x want %x", got, reply)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client TUN packet")
	}

	cancel()
	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("client shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client did not shut down")
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestDiagnosticUsesEveryPath(t *testing.T) {
	address := availableUDPAddress(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	serverTUN := tun.NewMemory("server-doctor", 16)
	serverMetrics := metrics.New("server")
	server, err := NewServer(config.Server{
		Listen:         address,
		TunnelAddress:  "10.77.0.1/24",
		MTU:            1280,
		ReorderWindow:  512,
		SessionTimeout: config.Duration(time.Minute),
		Clients: []config.ClientCredential{{
			Name: "doctor", ClientID: testClientID, PSK: testKey, TunnelAddress: "10.77.0.2/24",
		}},
	}, serverTUN, logger, serverMetrics)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Run(ctx)
	waitReady(t, serverMetrics)

	client, err := NewClient(config.Client{
		Server: address, ClientID: testClientID, PSK: testKey, TunnelAddress: "10.77.0.2/24",
		MTU: 1280, ReorderWindow: 512,
		Paths: []config.Path{{Name: "wifi", LocalAddress: "127.0.0.1", Weight: 1}, {Name: "usb", LocalAddress: "127.0.0.1", Weight: 1}},
	}, nil, logger, metrics.New("doctor"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Diagnose(ctx, 100*time.Millisecond, 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) != 2 || result.ReceivedBytes == 0 {
		t.Fatalf("unexpected diagnostic result: %#v", result)
	}
	for _, path := range result.Paths {
		if path.SentBytes == 0 || path.ReceivedBytes == 0 {
			t.Fatalf("path was not exercised: %#v", path)
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mu.RLock()
		session := server.sessionByClient[testClientID]
		server.mu.RUnlock()
		if session != nil && len(session.snapshotPaths()) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("diagnostic paths were not retired after close")
}

func TestManagedCredentialAuthorizationRotationAndRevocation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewServer(config.Server{
		TunnelAddress: "10.77.0.1/24",
		ReorderWindow: 512,
	}, tun.NewMemory("managed-server", 4), logger, metrics.New("server"))
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := protocol.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	credential := config.ClientCredential{
		Name:          "managed-laptop",
		ClientID:      testClientID,
		PSK:           firstKey,
		TunnelAddress: "10.77.0.3/24",
	}
	if err := server.AuthorizeClient(credential); err != nil {
		t.Fatal(err)
	}
	if server.credentialCount() != 1 {
		t.Fatalf("credential count=%d", server.credentialCount())
	}
	current, ok := server.credential(testClientID)
	if !ok {
		t.Fatal("managed credential was not installed")
	}
	if _, err := server.getOrCreateSession(current); err != nil {
		t.Fatal(err)
	}
	if _, ok := server.sessionByClient[testClientID]; !ok {
		t.Fatal("managed session was not created")
	}

	duplicateID, err := protocol.GenerateClientID()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.AuthorizeClient(config.ClientCredential{
		Name:          "duplicate-ip",
		ClientID:      duplicateID,
		PSK:           firstKey,
		TunnelAddress: "10.77.0.3/24",
	}); err == nil {
		t.Fatal("duplicate managed IP/key was accepted")
	}

	secondKey, err := protocol.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	credential.PSK = secondKey
	if err := server.AuthorizeClient(credential); err != nil {
		t.Fatal(err)
	}
	if _, ok := server.sessionByClient[testClientID]; ok {
		t.Fatal("key rotation did not terminate the old session")
	}

	server.RevokeClient(testClientID)
	if server.credentialCount() != 0 {
		t.Fatal("revoked managed credential remains authorized")
	}
}

func availableUDPAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().String()
	_ = conn.Close()
	return address
}

func waitReady(t *testing.T, registry *metrics.Registry) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if registry.Snapshot().Ready {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("service did not become ready")
}

func ipv4Packet(source, destination [4]byte, payload byte) []byte {
	packet := make([]byte, 21)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	packet[20] = payload
	return packet
}

func TestFixtureKey(t *testing.T) {
	if _, err := protocol.ParseKey(testKey); err != nil {
		t.Fatal(err)
	}
}
