package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Km103/LinkForge/internal/config"
)

func TestEnrollmentAPIAndClient(t *testing.T) {
	store, err := OpenStore(
		filepath.Join(t.TempDir(), "control.db"),
		[]byte("0123456789abcdef0123456789abcdef"),
		netip.MustParsePrefix("10.77.0.0/24"),
		[]netip.Addr{netip.MustParseAddr("10.77.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var mu sync.Mutex
	var authorized []config.ClientCredential
	var revoked []string
	service, err := NewService(config.Management{
		PublicRelay:   "127.0.0.1:4430",
		ActivationTTL: config.Duration(15 * time.Minute),
	}, store, strings.Repeat("a", 32), Hooks{
		Authorize: func(credential config.ClientCredential) error {
			mu.Lock()
			authorized = append(authorized, credential)
			mu.Unlock()
			return nil
		},
		Revoke: func(clientID string) {
			mu.Lock()
			revoked = append(revoked, clientID)
			mu.Unlock()
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.Handler())
	defer server.Close()

	unauthorized := jsonRequest(t, http.MethodPost, server.URL+"/v1/admin/activations", `{"user_id":"u","device_name":"laptop"}`, "")
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized admin status=%d", unauthorized.StatusCode)
	}
	_ = unauthorized.Body.Close()

	created := jsonRequest(t, http.MethodPost, server.URL+"/v1/admin/activations", `{"user_id":"user-1","device_name":"laptop"}`, strings.Repeat("a", 32))
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("activation status=%d body=%s", created.StatusCode, readBody(created))
	}
	var activation activationResponse
	if err := json.NewDecoder(created.Body).Decode(&activation); err != nil {
		t.Fatal(err)
	}
	_ = created.Body.Close()

	profile, err := FetchProfile(context.Background(), server.URL, activation.ActivationCode, "ubuntu-laptop", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if profile.ClientID == "" || profile.PSK == "" || profile.TrafficMode != "all" || !profile.AutoDiscoverPaths {
		t.Fatalf("invalid profile: %#v", profile)
	}
	mu.Lock()
	if len(authorized) != 1 || authorized[0].ClientID != profile.ClientID {
		t.Fatalf("relay hook not called: %#v", authorized)
	}
	mu.Unlock()
	if _, err := FetchProfile(context.Background(), server.URL, activation.ActivationCode, "again", "linux"); err == nil {
		t.Fatal("one-time activation code was reused")
	}

	list := jsonRequest(t, http.MethodGet, server.URL+"/v1/admin/devices", "", strings.Repeat("a", 32))
	body := readBody(list)
	if list.StatusCode != http.StatusOK || strings.Contains(body, profile.PSK) || strings.Contains(body, "encrypted_psk") {
		t.Fatalf("unsafe device list status=%d body=%s", list.StatusCode, body)
	}

	rotate := jsonRequest(t, http.MethodPost, server.URL+"/v1/admin/devices/"+profile.ClientID+"/rotate-key", `{}`, strings.Repeat("a", 32))
	if rotate.StatusCode != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotate.StatusCode, readBody(rotate))
	}
	var rotated enrollmentResponse
	if err := json.NewDecoder(rotate.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	_ = rotate.Body.Close()
	if rotated.Profile.PSK == profile.PSK {
		t.Fatal("rotation returned the old PSK")
	}

	revoke := jsonRequest(t, http.MethodDelete, server.URL+"/v1/admin/devices/"+profile.ClientID, "", strings.Repeat("a", 32))
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoke.StatusCode, readBody(revoke))
	}
	_ = revoke.Body.Close()
	mu.Lock()
	if len(revoked) != 1 || revoked[0] != profile.ClientID {
		t.Fatalf("revoke hook not called: %#v", revoked)
	}
	mu.Unlock()

	output := filepath.Join(t.TempDir(), "profile.json")
	if err := WriteProfile(output, rotated.Profile, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("profile mode=%v err=%v", info.Mode().Perm(), err)
	}
	if err := WriteProfile(output, rotated.Profile, false); err == nil {
		t.Fatal("existing profile was overwritten without force")
	}
}

func TestEnrollmentURLRequiresHTTPSAwayFromLoopback(t *testing.T) {
	for _, value := range []string{
		"http://example.com",
		"ftp://example.com",
		"https://user:pass@example.com",
	} {
		if _, err := enrollmentEndpoint(value); err == nil {
			t.Fatalf("unsafe enrollment URL accepted: %s", value)
		}
	}
	if _, err := enrollmentEndpoint("http://127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareProfilePathRejectsExistingDestination(t *testing.T) {
	output := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareProfilePath(output, false); err == nil {
		t.Fatal("existing profile destination was accepted")
	}
	if err := PrepareProfilePath(output, true); err != nil {
		t.Fatalf("replace destination rejected: %v", err)
	}
}

func TestRateLimiterIsBoundedAndExpiresWindows(t *testing.T) {
	limiter := newRateLimiter()
	now := time.Now()
	for index := 0; index < 4096; index++ {
		if !limiter.Allow(fmt.Sprintf("192.0.2.%d", index), 20, time.Minute, now) {
			t.Fatalf("key %d was rejected before the limiter reached capacity", index)
		}
	}
	if limiter.Allow("new-key", 20, time.Minute, now) {
		t.Fatal("limiter accepted an unbounded new key")
	}
	if !limiter.Allow("new-key", 20, time.Minute, now.Add(time.Minute)) {
		t.Fatal("expired limiter windows were not reclaimed")
	}
}

func jsonRequest(t *testing.T, method, url, body, token string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readBody(response *http.Response) string {
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	return string(body)
}
