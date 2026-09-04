package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tellor-io/bridge-remote-signer/logging"
	"github.com/tellor-io/bridge-remote-signer/metrics"
	"github.com/tellor-io/bridge-remote-signer/signer"
)

// Checker exposes HTTP liveness and readiness endpoints.
// These are intentionally separate from the gRPC server so that
// we can check health without needing gRPC support.
//
// Endpoints:
//
//	GET /healthz  — liveness:  is the process alive?
//	GET /readyz   — readiness: is the signer backend ready to sign?
//	GET /address  — the signer's bech32 account address (?prefix=..., default
//	                "tellor"). The address is public information derived from the
//	                public key, so it is served here without mTLS: consumers like
//	                the monitor discover it from the signer as the single source
//	                of truth, and fail loudly if the signer is unreachable.
//	                Signing itself remains exclusively behind the mTLS gRPC API.
//	GET /metrics  — Prometheus metrics. Currently exposes only `up` (set to 1
//	                while the process is serving), so a scraper can detect when
//	                the signer is down (no scrape / `up == 0`).
type Checker struct {
	signer     signer.Signer
	logger     *logging.Logger
	httpServer *http.Server
}

// New creates a Checker that listens on listenAddr (e.g. "0.0.0.0:9192").
// The health port should be different from the gRPC port and
// should NOT be exposed to the public.
func New(s signer.Signer, logger *logging.Logger, listenAddr string) *Checker {
	c := &Checker{
		signer: s,
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", c.liveness)
	mux.HandleFunc("/readyz", c.readiness)
	mux.Handle("/metrics", metricsHandler())
	mux.HandleFunc("/address", c.address)

	c.httpServer = &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return c
}

// metricsHandler serves the shared Prometheus registry (metrics package): `up`
// (always 1 while serving, so a scraper detects a down signer via `up == 0`) plus
// signer_active_node, updated by the sign handlers. No default Go/process collectors.
func metricsHandler() http.Handler {
	return promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})
}

// Start begins serving health check requests.
// Runs in the background called from a goroutine in main.go.
func (c *Checker) Start() error {
	c.logger.Info("health check server listening", "addr", c.httpServer.Addr)
	if err := c.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("health server error: %w", err)
	}
	return nil
}

// Stop shuts down the health check server gracefully.
func (c *Checker) Stop(ctx context.Context) error {
	return c.httpServer.Shutdown(ctx)
}

// liveness handles GET /healthz
// Returns 200 if the process is running. Never fails as long as the
// process is alive.
// address serves the signer's bech32 account address as JSON. Public data only
// (derived from the public key); no authentication, mirroring /metrics.
func (c *Checker) address(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		prefix = "tellor"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	addr, err := signer.Bech32Address(ctx, c.signer, prefix)
	if err != nil {
		c.logger.Error("address endpoint failed", "error", err)
		http.Error(w, fmt.Sprintf("derive address: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Address string `json:"address"`
	}{Address: addr})
}

func (c *Checker) liveness(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok")
}

// readiness handles GET /readyz
// Returns 200 if the signer backend is ready.
// Checks by calling GetPublicKey fast, read-only, confirms the key is loaded.
func (c *Checker) readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	_, err := c.signer.GetPublicKey(ctx)
	if err != nil {
		c.logger.Warn("readiness check failed", "error", err)
		http.Error(w, fmt.Sprintf("signer not ready: %v", err), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok")
}
