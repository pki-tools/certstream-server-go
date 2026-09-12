package certstream

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

// freePort asks the kernel for an unused port.
func freePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}

func baseConfig(t *testing.T) config.Config {
	t.Helper()

	var c config.Config
	c.Webserver.ListenAddr = "127.0.0.1"
	c.Webserver.ListenPort = freePort(t)
	c.Webserver.FullURL = "/full-stream"
	c.Webserver.LiteURL = "/"
	c.Webserver.DomainsOnlyURL = "/domains-only"
	c.General.BufferSizes.Websocket = 10
	c.General.BufferSizes.BroadcastManager = 10

	return c
}

// get returns the status code and body of a plain HTTP GET, retrying briefly
// while the listener comes up.
func get(t *testing.T, url string) (int, string) {
	t.Helper()

	var lastErr error
	for i := 0; i < 50; i++ {
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)

			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		return resp.StatusCode, string(body)
	}

	t.Fatalf("GET %s never succeeded: %v", url, lastErr)

	return 0, ""
}

// TestHealthEndpointIsNot426 is the regression test for the reported problem:
// a proxy health check hitting the websocket listener must get a 200, not the
// 426 that the websocket endpoints return for non-upgrade requests.
func TestHealthEndpointIsNot426(t *testing.T) {
	conf := baseConfig(t)
	config.AppConfig = conf

	cs, err := NewCertstreamServer(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.webserver.Stop()

	go cs.webserver.Start()

	base := fmt.Sprintf("http://127.0.0.1:%d", conf.Webserver.ListenPort)

	// The websocket root still rejects plain HTTP, which is what breaks httpchk.
	if code, _ := get(t, base+"/"); code != http.StatusUpgradeRequired {
		t.Errorf("websocket root returned %d, expected 426 (precondition)", code)
	}

	code, body := get(t, base+"/health")
	if code != http.StatusOK {
		t.Fatalf("/health returned %d, want 200 — health checks would still fail", code)
	}

	var h struct {
		Status        string `json:"status"`
		Version       string `json:"version"`
		UptimeSeconds int64  `json:"uptimeSeconds"`
	}
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		t.Fatalf("health body is not JSON: %v (%q)", err, body)
	}
	if h.Status != "ok" {
		t.Errorf("status = %q, want ok", h.Status)
	}
	if h.Version == "" {
		t.Error("health response omits version")
	}
}

// TestSplitListeners verifies that with webserver.ui enabled the dashboards move
// to their own port, the websocket port stops serving them, and both listeners
// answer health checks.
func TestSplitListeners(t *testing.T) {
	conf := baseConfig(t)
	conf.Webserver.UI.Enabled = true
	conf.Webserver.UI.ListenAddr = "127.0.0.1"
	conf.Webserver.UI.ListenPort = freePort(t)
	config.AppConfig = conf

	cs, err := NewCertstreamServer(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.webserver.Stop()

	if cs.uiServer == nil {
		t.Fatal("ui server was not created")
	}
	defer cs.uiServer.Stop()

	go cs.webserver.Start()
	go cs.uiServer.Start()

	ws := fmt.Sprintf("http://127.0.0.1:%d", conf.Webserver.ListenPort)
	ui := fmt.Sprintf("http://127.0.0.1:%d", conf.Webserver.UI.ListenPort)

	// Dashboards live on the UI listener only.
	if code, _ := get(t, ui+"/log-status"); code != http.StatusOK {
		t.Errorf("UI /log-status returned %d, want 200", code)
	}
	if code, _ := get(t, ws+"/log-status"); code != http.StatusNotFound {
		t.Errorf("websocket listener /log-status returned %d, want 404", code)
	}

	// Websockets stay on the websocket listener only.
	if code, _ := get(t, ws+"/full-stream"); code != http.StatusUpgradeRequired {
		t.Errorf("websocket /full-stream returned %d, want 426", code)
	}
	if code, _ := get(t, ui+"/full-stream"); code != http.StatusNotFound {
		t.Errorf("UI listener /full-stream returned %d, want 404", code)
	}

	// Both listeners must be health-checkable.
	for name, base := range map[string]string{"websocket": ws, "ui": ui} {
		if code, _ := get(t, base+"/health"); code != http.StatusOK {
			t.Errorf("%s listener /health returned %d, want 200", name, code)
		}
	}
}
