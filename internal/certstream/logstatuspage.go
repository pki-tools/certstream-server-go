package certstream

import (
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
)

var logStatusTmpl = template.Must(template.New("logstatus").Funcs(template.FuncMap{
	"formatNumber": func(n uint64) string {
		// Group digits with commas: 1234567 → 1,234,567
		s := fmt.Sprintf("%d", n)
		var b strings.Builder
		offset := len(s) % 3
		for i, c := range s {
			if i > 0 && (i-offset)%3 == 0 {
				b.WriteByte(',')
			}
			b.WriteRune(c)
		}
		return b.String()
	},
	"formatRate": func(r float64) string {
		if r < 0.1 {
			return fmt.Sprintf("%.2f", r)
		}
		if r < 10 {
			return fmt.Sprintf("%.1f", r)
		}
		return fmt.Sprintf("%.0f", r)
	},
	"formatETA": func(eta time.Duration, behind uint64) string {
		if eta == 0 {
			return "Live"
		}
		if eta < 0 || behind == 0 {
			return "—"
		}
		eta = eta.Round(time.Second)
		h := int(eta.Hours())
		m := int(math.Mod(eta.Minutes(), 60))
		s := int(math.Mod(eta.Seconds(), 60))
		switch {
		case h > 0:
			return fmt.Sprintf("%dh %dm", h, m)
		case m > 0:
			return fmt.Sprintf("%dm %ds", m, s)
		default:
			return fmt.Sprintf("%ds", s)
		}
	},
	"formatAge": func(d time.Duration) string {
		if d < 0 {
			return "Pending"
		}
		d = d.Round(time.Second)
		if d < time.Minute {
			return fmt.Sprintf("%ds ago", int(d.Seconds()))
		}
		if d < time.Hour {
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		}
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	},
	"etaClass": func(eta time.Duration) string {
		if eta == 0 {
			return "eta-live"
		}
		if eta < 0 {
			return "eta-unknown"
		}
		if eta < 10*time.Minute {
			return "eta-good"
		}
		if eta < time.Hour {
			return "eta-warn"
		}
		return "eta-bad"
	},
	"behindClass": func(behind uint64) string {
		if behind == 0 {
			return "status-live"
		}
		if behind < 10_000 {
			return "status-slight"
		}
		return "status-behind"
	},
	"typeClass": func(t string) string {
		if t == "Tiled" {
			return "badge-tiled"
		}
		return "badge-regular"
	},
	"catchupRemaining": func(until time.Time) string {
		if until.IsZero() {
			return ""
		}
		d := time.Until(until).Round(time.Second)
		if d <= 0 {
			return ""
		}
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if m > 0 {
			return fmt.Sprintf("%dm %ds", m, s)
		}
		return fmt.Sprintf("%ds", s)
	},
	"isCatchupActive": func(until time.Time) bool {
		return !until.IsZero() && time.Now().Before(until)
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="120">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CT Log Status</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1a1a1a;padding:24px 32px;min-height:100vh}
h1{font-size:1.375rem;font-weight:700;margin-bottom:4px;letter-spacing:-0.01em}
.meta{font-size:0.8125rem;color:#6b7280;margin-bottom:20px}
.meta strong{color:#374151}
.wrap{overflow-x:auto;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.12),0 0 0 1px rgba(0,0,0,.05)}
table{width:100%;border-collapse:collapse;background:#fff;font-size:0.8125rem}
thead tr{background:#1e293b}
th{padding:10px 14px;text-align:left;color:#cbd5e1;font-weight:600;font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
td{padding:9px 14px;border-bottom:1px solid #f1f5f9;vertical-align:middle;white-space:nowrap}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#f8fafc}
.num{font-variant-numeric:tabular-nums;font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:0.8rem}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:0.6875rem;font-weight:600;letter-spacing:.02em}
.badge-regular{background:#dbeafe;color:#1d4ed8}
.badge-tiled{background:#ede9fe;color:#6d28d9}
.badge-catchup{background:#fef9c3;color:#854d0e}
.eta-live{color:#15803d;font-weight:700}
.eta-good{color:#16a34a}
.eta-warn{color:#d97706}
.eta-bad{color:#dc2626;font-weight:600}
.eta-unknown{color:#9ca3af}
.status-live{color:#15803d}
.status-slight{color:#d97706}
.status-behind{color:#dc2626}
.age{color:#9ca3af}
button.catchup-btn{border:none;background:#3b82f6;color:#fff;font-size:0.6875rem;font-weight:600;padding:3px 10px;border-radius:6px;cursor:pointer;white-space:nowrap}
button.catchup-btn:hover{background:#2563eb}
button.catchup-btn:disabled{background:#93c5fd;cursor:default}
</style>
</head>
<body>
<h1>CT Log Status</h1>
<p class="meta">
  Generated at <strong>{{.GeneratedAt}}</strong> &nbsp;·&nbsp;
  <strong>{{.TotalLogs}}</strong> logs monitored &nbsp;·&nbsp;
  Tree sizes refresh every 3 min &nbsp;·&nbsp; Page auto-refreshes every 2 min
</p>
<div class="wrap">
<table>
<thead>
<tr>
  <th>Operator</th>
  <th>Log Name</th>
  <th>Type</th>
  <th>Current Index</th>
  <th>Tree Size</th>
  <th>Behind</th>
  <th>Rate (e/s)</th>
  <th>Est. Catch-up</th>
  <th>Tree Size Age</th>
  <th></th>
</tr>
</thead>
<tbody>
{{range .Logs}}
<tr>
  <td>{{.Operator}}</td>
  <td>{{.Name}}</td>
  <td>
    <span class="badge {{typeClass .Type}}">{{.Type}}</span>
    {{if isCatchupActive .CatchupUntil}}<span class="badge badge-catchup" title="Catch-up active for {{catchupRemaining .CatchupUntil}} more">&#9889; {{catchupRemaining .CatchupUntil}}</span>{{end}}
  </td>
  <td class="num">{{formatNumber .CurrentIndex}}</td>
  <td class="num">{{if gt .TreeSize 0}}{{formatNumber .TreeSize}}{{else}}<span class="age">Pending</span>{{end}}</td>
  <td class="num {{behindClass .Behind}}">{{if gt .TreeSize 0}}{{if eq .Behind 0}}—{{else}}{{formatNumber .Behind}}{{end}}{{else}}<span class="age">—</span>{{end}}</td>
  <td class="num">{{if gt .RatePerSec 0.0}}{{formatRate .RatePerSec}}{{else}}<span class="age">—</span>{{end}}</td>
  <td class="{{etaClass .ETA}}">{{formatETA .ETA .Behind}}</td>
  <td class="age">{{formatAge .TreeSizeAge}}</td>
  <td><button class="catchup-btn" onclick="triggerCatchup(this,'{{.URL}}')" {{if isCatchupActive .CatchupUntil}}disabled{{end}}>{{if isCatchupActive .CatchupUntil}}Catching up…{{else}}Catch Up{{end}}</button></td>
</tr>
{{end}}
</tbody>
</table>
</div>
<script>
function triggerCatchup(btn, url) {
  btn.disabled = true;
  btn.textContent = 'Sending…';
  fetch('/log-status/catchup', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'url=' + encodeURIComponent(url)
  }).then(function(r) {
    if (r.ok) {
      btn.textContent = 'Catching up…';
    } else {
      btn.disabled = false;
      btn.textContent = 'Catch Up';
    }
  }).catch(function() {
    btn.disabled = false;
    btn.textContent = 'Catch Up';
  });
}
</script>
</body>
</html>`))

type logStatusPageData struct {
	GeneratedAt string
	TotalLogs   int
	Logs        []certificatetransparency.LogStatusSnapshot
}

// catchupDuration is how long catch-up mode stays active after a trigger.
const catchupDuration = 10 * time.Minute

// catchupHandler accepts a POST with form field "url" and activates catch-up mode
// for that log for catchupDuration. It responds 204 on success, 400 on bad input,
// 404 if the log is not known.
func catchupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rawURL := strings.TrimSpace(r.FormValue("url"))
	if rawURL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	normURL := certificatetransparency.NormalizeCtlogURL(rawURL)
	if !certificatetransparency.IsKnownLog(normURL) {
		http.Error(w, "unknown log", http.StatusNotFound)
		return
	}
	certificatetransparency.TriggerCatchup(normURL, catchupDuration)
	w.WriteHeader(http.StatusNoContent)
}

func logStatusHandler(w http.ResponseWriter, _ *http.Request) {
	logs := certificatetransparency.GetLogStatuses()

	data := logStatusPageData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		TotalLogs:   len(logs),
		Logs:        logs,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := logStatusTmpl.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
