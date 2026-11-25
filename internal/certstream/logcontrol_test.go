package certstream

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

const (
	controlledLog = "https://ct.example.com/controlled"
	allowedIP     = "203.0.113.9"
	otherIP       = "198.51.100.1"
)

// setupControls configures the allow-list and a known log, and restores both
// afterwards. The allow-list is built once per process, so it is reset too.
func setupControls(t *testing.T, allowed []string) {
	t.Helper()

	prev := config.AppConfig.General.LogControls.AllowedIPs
	config.AppConfig.General.LogControls.AllowedIPs = allowed
	controlAllowOnce = sync.Once{}

	certificatetransparency.RegisterLogForTest(controlledLog, "controlled", "Example")
	certificatetransparency.ResetLogControlsForTest()

	t.Cleanup(func() {
		config.AppConfig.General.LogControls.AllowedIPs = prev
		controlAllowOnce = sync.Once{}
		certificatetransparency.ResetLogControlsForTest()
	})
}

// control sends a control request as the page's JavaScript does, from ip,
// optionally without the required header.
func control(t *testing.T, path, ip, action string, withHeader bool) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{"url": {controlledLog}, "action": {action}}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":40000"

	if withHeader {
		req.Header.Set(controlHeader, "1")
	}

	rec := httptest.NewRecorder()

	switch path {
	case "/log-status/catchup":
		catchupHandler(rec, req)
	default:
		controlHandler(rec, req)
	}

	return rec
}

func state() certificatetransparency.LogState {
	return certificatetransparency.GetLogState(certificatetransparency.NormalizeCtlogURL(controlledLog))
}

// TestControlsRefuseByDefault: with no allow-list configured, nothing may
// control ingestion - not even from localhost.
func TestControlsRefuseByDefault(t *testing.T) {
	setupControls(t, nil)

	for _, ip := range []string{"127.0.0.1", allowedIP} {
		rec := control(t, "/log-status/control", ip, "pause", true)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "disabled") {
			t.Errorf("from %s with no allow-list: %d %q, want 403 disabled", ip, rec.Code, rec.Body.String())
		}
	}

	if state() != certificatetransparency.LogRunning {
		t.Error("a refused request changed the log's state")
	}
}

// TestControlsRequireAllowedAddressAndHeader covers both checks separately:
// an allowed address without the header (what a cross-site form submission
// from the operator's own browser would look like) and the header from an
// address that is not allowed.
func TestControlsRequireAllowedAddressAndHeader(t *testing.T) {
	setupControls(t, []string{allowedIP})

	if rec := control(t, "/log-status/control", allowedIP, "pause", false); rec.Code != http.StatusForbidden {
		t.Errorf("allowed address without header: %d, want 403", rec.Code)
	}

	if rec := control(t, "/log-status/control", otherIP, "pause", true); rec.Code != http.StatusForbidden {
		t.Errorf("header from an address not allowed: %d, want 403", rec.Code)
	}

	// The original catch-up endpoint was unguarded; it is not any more.
	if rec := control(t, "/log-status/catchup", otherIP, "", true); rec.Code != http.StatusForbidden {
		t.Errorf("legacy catch-up endpoint from an address not allowed: %d, want 403", rec.Code)
	}

	if state() != certificatetransparency.LogRunning {
		t.Error("a refused request changed the log's state")
	}

	req := httptest.NewRequest(http.MethodGet, "/log-status/control", nil)
	req.RemoteAddr = allowedIP + ":1"
	req.Header.Set(controlHeader, "1")

	rec := httptest.NewRecorder()
	controlHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d, want 405", rec.Code)
	}
}

// TestControlsStateMachine walks the allowed transitions and the refused ones.
func TestControlsStateMachine(t *testing.T) {
	setupControls(t, []string{"203.0.113.0/24"})

	steps := []struct {
		action string
		code   int
		state  certificatetransparency.LogState
	}{
		{"catchup", http.StatusNoContent, certificatetransparency.LogRunning},
		{"pause", http.StatusNoContent, certificatetransparency.LogPaused},
		{"catchup", http.StatusConflict, certificatetransparency.LogPaused},
		{"stop", http.StatusNoContent, certificatetransparency.LogStopped},
		{"pause", http.StatusConflict, certificatetransparency.LogStopped},
		{"resume", http.StatusNoContent, certificatetransparency.LogRunning},
		{"stop", http.StatusNoContent, certificatetransparency.LogStopped},
		{"resume", http.StatusNoContent, certificatetransparency.LogRunning},
		{"explode", http.StatusBadRequest, certificatetransparency.LogRunning},
	}

	for i, step := range steps {
		rec := control(t, "/log-status/control", allowedIP, step.action, true)

		if rec.Code != step.code {
			t.Fatalf("step %d %s: status %d (%q), want %d", i, step.action, rec.Code, rec.Body.String(), step.code)
		}

		if got := state(); got != step.state {
			t.Fatalf("step %d %s: state %s, want %s", i, step.action, got, step.state)
		}
	}

	form := url.Values{"url": {"https://ct.example.com/no-such-log"}, "action": {"pause"}}
	req := httptest.NewRequest(http.MethodPost, "/log-status/control", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(controlHeader, "1")
	req.RemoteAddr = allowedIP + ":1"

	rec := httptest.NewRecorder()
	controlHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown log: %d, want 404", rec.Code)
	}
}

// controlledRow renders /log-status for a viewer at ip and returns the table
// row for the controlled log.
func controlledRow(t *testing.T, ip string) string {
	t.Helper()

	body := renderLogStatus(t, ip)

	i := strings.Index(body, ">controlled<")
	if i < 0 {
		t.Fatal("controlled log missing from the page")
	}

	start := strings.LastIndex(body[:i], "<tr>")
	end := strings.Index(body[i:], "</tr>")

	return body[start : i+end]
}

// TestLogStatusPageControls checks what the page offers: the right buttons for
// each state, enabled only for an allowed viewer, with the reason given
// otherwise.
func TestLogStatusPageControls(t *testing.T) {
	setupControls(t, []string{allowedIP})

	row := controlledRow(t, allowedIP)
	for _, want := range []string{`aria-label="Catch up"`, `aria-label="Pause"`, `aria-label="Stop"`} {
		if !strings.Contains(row, want) {
			t.Errorf("running log, allowed viewer: missing %s", want)
		}
	}

	// Pause and Stop must be usable. Catch up may be disabled, but only
	// because catch-up is already active - which an earlier test in this
	// process can leave it.
	for _, label := range []string{"Pause", "Stop"} {
		if b := buttonTag(row, label); strings.Contains(b, " disabled") {
			t.Errorf("running log, allowed viewer: %s rendered disabled: %s", label, b)
		}
	}

	if b := buttonTag(row, "Catch up"); strings.Contains(b, " disabled") && !strings.Contains(b, "Catching up for") {
		t.Errorf("running log, allowed viewer: Catch up disabled without catch-up being active: %s", b)
	}

	if strings.Contains(row, `aria-label="Resume"`) {
		t.Error("running log offers Resume")
	}

	// Disabled buttons show no tooltip in Chrome, so the reason must be on
	// the page itself, with the address the server sees.
	if page := renderLogStatus(t, otherIP); !strings.Contains(page, "read-only from your address") || !strings.Contains(page, otherIP) {
		t.Error("a viewer not allowed should see a note naming their address")
	}

	if page := renderLogStatus(t, allowedIP); strings.Contains(page, `class="ctl-note"`) {
		t.Error("an allowed viewer should not see the read-only note")
	}

	denied := controlledRow(t, otherIP)
	if strings.Count(denied, " disabled") < 3 || !strings.Contains(denied, "not in general.log_controls.allowed_ips") {
		t.Errorf("viewer not allowed: controls should be disabled with the reason:\n%s", denied)
	}

	_ = control(t, "/log-status/control", allowedIP, "pause", true)

	row = controlledRow(t, allowedIP)
	if !strings.Contains(row, `aria-label="Resume"`) || !strings.Contains(row, `aria-label="Stop"`) ||
		strings.Contains(row, `aria-label="Pause"`) || !strings.Contains(row, "Paused") {
		t.Errorf("paused log should show Paused, Resume and Stop:\n%s", row)
	}

	_ = control(t, "/log-status/control", allowedIP, "stop", true)

	row = controlledRow(t, allowedIP)
	if !strings.Contains(row, `aria-label="Resume"`) || strings.Contains(row, `aria-label="Stop"`) || !strings.Contains(row, "Stopped") {
		t.Errorf("stopped log should show Stopped and Resume only:\n%s", row)
	}

	setupControls(t, nil)

	if off := controlledRow(t, allowedIP); !strings.Contains(off, "Log controls are disabled") {
		t.Errorf("with no allow-list the controls should explain they are disabled:\n%s", off)
	}
}

// buttonTag returns the opening tag of the button with the given aria-label.
func buttonTag(row, label string) string {
	i := strings.Index(row, `aria-label="`+label+`"`)
	if i < 0 {
		return ""
	}

	start := strings.LastIndex(row[:i], "<button")
	end := strings.Index(row[i:], ">")

	return row[start : i+end+1]
}

// renderLogStatus renders /log-status for a viewer at ip.
func renderLogStatus(t *testing.T, ip string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/log-status", nil)
	req.RemoteAddr = ip + ":40000"

	rec := httptest.NewRecorder()
	logStatusHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("log-status: %d", rec.Code)
	}

	return rec.Body.String()
}
