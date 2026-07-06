// Package metrics holds the shared Prometheus registry for the signer, served at
// /metrics by the health server and updated by the sign handlers.
package metrics

import (
	"net"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Registry is the shared registry exposed at /metrics. No default Go/process
// collectors, so the output is exactly the metrics defined here.
var Registry = prometheus.NewRegistry()

var (
	up = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "up",
		Help: "Whether the bridge signer is up and serving (always 1 when scrapeable).",
	})

	// activeNode is 1 for the node IP whose signature was most recently accepted, and
	// 0 for every other node the signer has seen. A signing-node switch (failover)
	// flips two series, so changes(signer_active_node[...]) detects it for alerting.
	activeNode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "signer_active_node",
		Help: "1 for the node IP whose signature was most recently accepted, 0 for others.",
	}, []string{"ip"})

	mu    sync.Mutex
	seen  = map[string]struct{}{}
)

func init() {
	up.Set(1)
	Registry.MustRegister(up, activeNode)
}

// RecordSign marks the given peer address's IP as the current signing node: its gauge
// is set to 1 and every previously-seen node's gauge to 0. The ephemeral port is
// stripped so reconnects from the same node don't look like a switch. Call it after a
// signature is accepted (SignBridgeCheckpoint / SignOracleAttestation).
func RecordSign(remoteAddr string) {
	ip := hostOnly(remoteAddr)
	if ip == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	seen[ip] = struct{}{}
	for s := range seen {
		if s == ip {
			activeNode.WithLabelValues(s).Set(1)
			continue
		}
		activeNode.WithLabelValues(s).Set(0)
	}
}

// hostOnly strips the ephemeral port from a "host:port" peer address; the port changes
// per gRPC connection and would otherwise look like a node switch.
func hostOnly(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
