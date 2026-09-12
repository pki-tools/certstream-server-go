package certstream

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

var startedAt = time.Now()

// healthHandler answers liveness and readiness checks with a plain 200.
//
// The websocket endpoints reject non-websocket requests with 426 Upgrade
// Required, which most load balancers (HAProxy's httpchk included) treat as a
// failure. This gives them something unambiguous to probe, and is registered on
// every listener so whichever port a proxy checks has one.
//
// It reports "ok" whenever the process is serving. Deliberately so: tying the
// status to whether logs are keeping up would take the server out of rotation
// during a backlog, when it is still perfectly able to serve clients.
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	body := struct {
		Status        string `json:"status"`
		Version       string `json:"version"`
		UptimeSeconds int64  `json:"uptimeSeconds"`
		LogsMonitored int    `json:"logsMonitored"`
		Certificates  int64  `json:"certificates"`
		Precertifs    int64  `json:"precertificates"`
	}{
		Status:        "ok",
		Version:       config.Version,
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		LogsMonitored: certificatetransparency.CountMonitoredLogs(),
		Certificates:  certificatetransparency.GetProcessedCerts(),
		Precertifs:    certificatetransparency.GetProcessedPrecerts(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(body)
}
