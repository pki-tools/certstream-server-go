package certstream

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

// Log controls - pause, stop, resume and catch-up - change what the server
// ingests, so every request has to pass two checks before it is acted on.
//
//  1. The client's address is in general.log_controls.allowed_ips. An empty
//     list disables the controls outright rather than leaving them open. The
//     address is taken the same way the listener's own whitelist takes it, so
//     behind a reverse proxy it is the client's only when real_ip is set.
//
//  2. The request carries the X-Certstream-Control header. An address check
//     alone is not enough: any website the operator visits could make their
//     browser - at an allowed address - submit a form to these endpoints. A
//     cross-site page cannot attach a custom header without a CORS preflight,
//     which this server never grants, so requiring one confines the controls
//     to this server's own pages and to deliberate tools such as curl.

// controlHeader must be present on every control request; see above.
const controlHeader = "X-Certstream-Control"

var (
	controlAllowOnce sync.Once
	controlAllow     *web.IPAllowList
)

func controlAllowList() *web.IPAllowList {
	controlAllowOnce.Do(func() {
		var invalid []string

		controlAllow, invalid = web.NewIPAllowList(config.AppConfig.General.LogControls.AllowedIPs)
		for _, entry := range invalid {
			log.Println("Ignoring invalid entry in general.log_controls.allowed_ips: ", entry)
		}
	})

	return controlAllow
}

// controlsAllowedFor reports whether the client making r may use the controls,
// which decides whether the page renders them enabled.
func controlsAllowedFor(r *http.Request) bool {
	return r != nil && controlAllowList().Contains(web.ClientIP(r))
}

// authorizeControl applies both checks, writing the refusal itself.
func authorizeControl(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	if r.Header.Get(controlHeader) == "" {
		http.Error(w, "missing "+controlHeader+" header", http.StatusForbidden)
		return false
	}

	allow := controlAllowList()
	if allow.Empty() {
		http.Error(w, "log controls are disabled: list permitted addresses in general.log_controls.allowed_ips", http.StatusForbidden)
		return false
	}

	if !allow.Contains(web.ClientIP(r)) {
		log.Printf("Log control refused for %s: address not in general.log_controls.allowed_ips\n", r.RemoteAddr)
		http.Error(w, "your address is not permitted to use log controls", http.StatusForbidden)

		return false
	}

	return true
}

// controlHandler accepts a POST with form fields "url" and "action" (catchup,
// pause, stop or resume) and answers 204 on success.
func controlHandler(w http.ResponseWriter, r *http.Request) {
	if !authorizeControl(w, r) {
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	normURL, ok := controlTarget(w, r)
	if !ok {
		return
	}

	action := strings.TrimSpace(r.FormValue("action"))
	state := certificatetransparency.GetLogState(normURL)

	switch action {
	case "catchup":
		if state != certificatetransparency.LogRunning {
			http.Error(w, fmt.Sprintf("log is %s; resume it first", state), http.StatusConflict)
			return
		}

		certificatetransparency.TriggerCatchup(normURL, catchupDuration)
	case "pause":
		if state == certificatetransparency.LogStopped {
			http.Error(w, "log is stopped; resume it first", http.StatusConflict)
			return
		}

		setStateOrFail(w, normURL, certificatetransparency.LogPaused)
		return
	case "stop":
		setStateOrFail(w, normURL, certificatetransparency.LogStopped)
		return
	case "resume":
		setStateOrFail(w, normURL, certificatetransparency.LogRunning)
		return
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func setStateOrFail(w http.ResponseWriter, normURL string, state certificatetransparency.LogState) {
	if err := certificatetransparency.SetLogState(normURL, state); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// controlTarget resolves the "url" field to a known log.
func controlTarget(w http.ResponseWriter, r *http.Request) (string, bool) {
	rawURL := strings.TrimSpace(r.FormValue("url"))
	if rawURL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return "", false
	}

	normURL := certificatetransparency.NormalizeCtlogURL(rawURL)
	if !certificatetransparency.IsKnownLog(normURL) {
		http.Error(w, "unknown log", http.StatusNotFound)
		return "", false
	}

	return normURL, true
}
