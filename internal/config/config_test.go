package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
