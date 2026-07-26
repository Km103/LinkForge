//go:build linux

package netconfig

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestProtectRelayCreatesAndCleansSourcePolicy(t *testing.T) {
	var mu sync.Mutex
	var commands []string
	runner := func(_ context.Context, command string, args ...string) ([]byte, error) {
		joined := command + " " + strings.Join(args, " ")
		mu.Lock()
		commands = append(commands, joined)
		mu.Unlock()
		if joined == "ip -4 route show default dev lo" {
			return []byte("default via 127.0.0.1 dev lo\n"), nil
		}
		return nil, nil
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	guard, err := protectRelay(context.Background(), "127.0.0.1:4430", []PhysicalPath{{Name: "test", Interface: "lo", LocalAddress: "127.0.0.1"}}, logger, runner)
	if err != nil {
		t.Fatal(err)
	}
	guard.Close(context.Background())
	output := strings.Join(commands, "\n")
	for _, expected := range []string{"ip rule add priority", "from 127.0.0.1/32 table", "ip route replace table", "ip rule del priority", "ip route flush table"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing %q in commands:\n%s", expected, output)
		}
	}
}
