package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDashboardStatusAndPrometheusEndpoints(t *testing.T) {
	registry := New("client")
	registry.SetReady(true)
	registry.SentBytes.Store(1234)
	registry.ReorderSkips.Store(2)
	path := registry.Path("wifi")
	path.Healthy.Store(true)
	path.SentBytes.Store(1000)

	for endpoint, contentType := range map[string]string{
		"/":              "text/html",
		"/api/v1/status": "application/json",
		"/metrics":       "text/plain",
	} {
		request := httptest.NewRequest(http.MethodGet, endpoint, nil)
		response := httptest.NewRecorder()
		registry.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d", endpoint, response.Code)
		}
		if !strings.Contains(response.Header().Get("Content-Type"), contentType) {
			t.Fatalf("%s content type = %q", endpoint, response.Header().Get("Content-Type"))
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, request)
	var status Status
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.SentBytes != 1234 || status.ReorderSkips != 2 || len(status.Paths) != 1 {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestControlRequiresCapabilityToken(t *testing.T) {
	registry := New("client")
	var starts atomic.Int32
	token, err := registry.EnableControl(&Control{
		Start: func() error { starts.Add(1); return nil },
		Stop:  func() error { return nil },
		State: func() ControlStatus { return ControlStatus{State: "stopped"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/control/start", nil)
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || starts.Load() != 0 {
		t.Fatal("unauthenticated browser request reached tunnel control")
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/control/start", nil)
	request.Header.Set("X-LinkForge-Control", token)
	response = httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || starts.Load() != 1 {
		t.Fatalf("authenticated control failed: status=%d starts=%d", response.Code, starts.Load())
	}
}
