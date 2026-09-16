package health

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tellor-io/bridge-remote-signer/logging"
)

// stubSigner satisfies signer.Signer for the metrics handler test.
// The metrics endpoint does not call the signer, so these return zero values.
type stubSigner struct{}

func (stubSigner) Sign(context.Context, []byte) ([]byte, error)    { return nil, nil }
func (stubSigner) SignRaw(context.Context, []byte) ([]byte, error) { return nil, nil }
func (stubSigner) GetPublicKey(context.Context) ([]byte, error)    { return nil, nil }

// TestMetricsEndpointExposesOnlyUp verifies that GET /metrics serves the
// Prometheus `up` gauge set to 1, and that it is the ONLY metric exposed
// (no default Go/process collectors) — i.e. "for now only add the up metric".
func TestMetricsEndpointExposesOnlyUp(t *testing.T) {
	srv := httptest.NewServer(metricsHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	if !strings.Contains(out, "\nup 1\n") && !strings.HasPrefix(out, "up 1\n") {
		t.Fatalf("expected `up 1` sample, got:\n%s", out)
	}

	// Confirm `up` is the only metric: no Go runtime or process collectors leaked.
	for _, unwanted := range []string{"go_", "process_", "promhttp_"} {
		if strings.Contains(out, "\n"+unwanted) || strings.HasPrefix(out, unwanted) {
			t.Fatalf("unexpected metric prefix %q in output (should be only `up`):\n%s", unwanted, out)
		}
	}
}

// TestMetricsHandlerRegisteredOnChecker verifies the /metrics route is wired
// into the Checker's HTTP mux (not just the standalone handler).
func TestMetricsHandlerRegisteredOnChecker(t *testing.T) {
	logger, err := logging.New("error", "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	c := New(stubSigner{}, logger, "127.0.0.1:0")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	c.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "up 1") {
		t.Fatalf("expected `up 1` from /metrics route, got:\n%s", rec.Body.String())
	}
}

// The /address endpoint serves the bech32 address without authentication — the
// monitor's single source of truth for the reporter identity.
func TestAddressEndpoint(t *testing.T) {
	pub, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	logger, err := logging.New("error", "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	c := New(pubStubSigner{pub: pub}, logger, "127.0.0.1:0")

	rec := httptest.NewRecorder()
	c.address(rec, httptest.NewRequest("GET", "/address", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}
	var out struct{ Address string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if !strings.HasPrefix(out.Address, "tellor1") {
		t.Fatalf("address %q lacks default prefix", out.Address)
	}

	// A signer that cannot provide a key must fail loudly, never return a guess.
	rec = httptest.NewRecorder()
	c2 := New(stubSigner{}, logger, "127.0.0.1:0")
	c2.address(rec, httptest.NewRequest("GET", "/address", nil))
	if rec.Code != 500 {
		t.Fatalf("expected 500 for unavailable key, got %d", rec.Code)
	}
}

type pubStubSigner struct {
	stubSigner
	pub []byte
}

func (p pubStubSigner) GetPublicKey(context.Context) ([]byte, error) { return p.pub, nil }
