package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadClientStrictAndDefaults(t *testing.T) {
	t.Setenv("TEST_LINKFORGE_KEY", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=")
	path := writeConfig(t, `{
        "server":"127.0.0.1:4430",
        "client_id":"67c42c03753048d285b2e7437299235d",
        "psk_env":"TEST_LINKFORGE_KEY",
        "tunnel_address":"10.77.0.2/24",
        "paths":[{"name":"wifi","local_address":"127.0.0.1","weight":3}]
    }`)
	client, err := LoadClient(path)
	if err != nil {
		t.Fatal(err)
	}
	if client.MTU != DefaultMTU || client.ReorderWindow != 512 || client.TunnelName == "" {
		t.Fatalf("defaults were not applied: %#v", client)
	}
}

func TestLoadRejectsUnknownAndTrailingData(t *testing.T) {
	for _, body := range []string{
		`{"server":"127.0.0.1:1","unknown":true}`,
		`{} {}`,
	} {
		_, err := LoadClient(writeConfig(t, body))
		if err == nil {
			t.Fatalf("invalid config accepted: %s", body)
		}
	}
}

func TestServerRejectsKeyReuseAndOutOfSubnetIP(t *testing.T) {
	key := "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
	server := Server{
		Listen: ":4430", TunnelAddress: "10.77.0.1/24", MTU: 1280, ReorderWindow: 512,
		Logging: Logging{Level: "info", Format: "json"},
		Clients: []ClientCredential{
			{Name: "one", ClientID: "67c42c03753048d285b2e7437299235d", PSK: key, TunnelAddress: "10.77.0.2/24"},
			{Name: "two", ClientID: "77c42c03753048d285b2e7437299235d", PSK: key, TunnelAddress: "10.88.0.2/24"},
		},
	}
	err := server.Validate()
	if err == nil || (!strings.Contains(err.Error(), "reuses") && !strings.Contains(err.Error(), "usable address")) {
		t.Fatalf("unexpected validation result: %v", err)
	}
}

func TestManagementValidationAndSecrets(t *testing.T) {
	management := Management{
		Listen:        "127.0.0.1:8443",
		DatabasePath:  filepath.Join(t.TempDir(), "control.db"),
		PublicRelay:   "127.0.0.1:4430",
		TunnelPool:    "10.77.0.0/24",
		AdminTokenEnv: "TEST_ADMIN_TOKEN",
		MasterKeyEnv:  "TEST_MASTER_KEY",
		ActivationTTL: Duration(15 * time.Minute),
	}
	if err := management.Validate(netip.MustParsePrefix("10.77.0.1/24")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("TEST_MASTER_KEY", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=")
	token, key, err := management.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 32 || len(key) != 32 {
		t.Fatalf("unexpected secret lengths: %d %d", len(token), len(key))
	}
	management.Listen = "0.0.0.0:8443"
	if err := management.Validate(netip.MustParsePrefix("10.77.0.1/24")); err == nil {
		t.Fatal("non-loopback management listener was accepted")
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
