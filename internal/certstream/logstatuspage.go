package certstream

import (
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

func logStatusFuncs() template.FuncMap {
	return template.FuncMap{
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
		// Sort keys mirror the display logic above so the ordering matches what the
		// cell actually shows: 0 is live, -1 is unknown, otherwise seconds.
		"etaSort": func(eta time.Duration, behind uint64) int64 {
			if eta == 0 {
				return 0
			}
			if eta < 0 || behind == 0 {
				return -1
			}
			return int64(eta.Seconds())
		},
		"ageSort": func(d time.Duration) int64 {
			if d < 0 {
				return -1
			}
			return int64(d.Seconds())
		},
	}
}

// logStatusTableMarkup is the sortable table on its own, shared by /log-status
// and the combined /overview page.
const logStatusTableMarkup = `{{if not .ControlsAllowed}}<p class="ctl-note">{{if .ControlsConfigured}}Log controls are read-only from your address{{if .ViewerIP}} (<code>{{.ViewerIP}}</code>){{end}}. Permitted addresses are set in <code>general.log_controls.allowed_ips</code>.{{else}}Log controls are disabled. To enable them, list permitted addresses in <code>general.log_controls.allowed_ips</code>{{if .ViewerIP}} - this server sees you as <code>{{.ViewerIP}}</code>{{end}}.{{end}}</p>{{end}}
<div class="wrap">
<table id="logtable">
<thead>
<tr>
  <th class="sortable" data-col="0" data-type="text">Operator<i></i></th>
  <th class="sortable" data-col="1" data-type="text">Log Name<i></i></th>
  <th class="sortable" data-col="2" data-type="text">Type<i></i></th>
  <th class="sortable" data-col="3" data-type="num">Current Index<i></i></th>
  <th class="sortable" data-col="4" data-type="num">Tree Size<i></i></th>
  <th class="sortable" data-col="5" data-type="num">Behind<i></i></th>
  <th class="sortable" data-col="6" data-type="num">Rate (e/s)<i></i></th>
  <th class="sortable" data-col="7" data-type="num">Est. Catch-up<i></i></th>
  <th class="sortable" data-col="8" data-type="num">Tree Size Age<i></i></th>
  <th></th>
</tr>
</thead>
<tbody>
{{$deny := ""}}{{if not .ControlsConfigured}}{{$deny = "Log controls are disabled: set general.log_controls.allowed_ips"}}{{else if not .ControlsAllowed}}{{$deny = "Your address is not in general.log_controls.allowed_ips"}}{{end}}
{{range .Logs}}
<tr>
  <td data-sort="{{.Operator}}">{{.Operator}}</td>
  <td data-sort="{{.Name}}">{{.Name}}</td>
  <td data-sort="{{.Type}}">
    <span class="badge {{typeClass .Type}}">{{.Type}}</span>
    {{if eq .State "paused"}}<span class="badge badge-paused" title="Ingestion paused by an operator; resumes where it left off">&#10074;&#10074; Paused</span>{{else if eq .State "stopped"}}<span class="badge badge-stopped" title="Ingestion stopped by an operator; stays stopped across restarts until resumed">&#9632; Stopped</span>{{end}}
    {{if isCatchupActive .CatchupUntil}}<span class="badge badge-catchup" title="Catch-up active for {{catchupRemaining .CatchupUntil}} more">&#9889; {{catchupRemaining .CatchupUntil}}</span>{{end}}
    {{if .Proxy}}<span class="badge badge-proxy" title="Fetched via egress proxy {{.Proxy}}">&#8644; {{.Proxy}}</span>{{end}}
  </td>
  <td class="num" data-sort="{{.CurrentIndex}}">{{formatNumber .CurrentIndex}}</td>
  <td class="num" data-sort="{{.TreeSize}}">{{if gt .TreeSize 0}}{{formatNumber .TreeSize}}{{else}}<span class="age">Pending</span>{{end}}</td>
  <td class="num {{behindClass .Behind}}" data-sort="{{.Behind}}">{{if gt .TreeSize 0}}{{if eq .Behind 0}}—{{else}}{{formatNumber .Behind}}{{end}}{{else}}<span class="age">—</span>{{end}}</td>
  <td class="num" data-sort="{{.RatePerSec}}">{{if gt .RatePerSec 0.0}}{{formatRate .RatePerSec}}{{else}}<span class="age">—</span>{{end}}</td>
  <td class="{{etaClass .ETA}}" data-sort="{{etaSort .ETA .Behind}}">{{if eq .State "running"}}{{formatETA .ETA .Behind}}{{else}}<span class="age">{{.State}}</span>{{end}}</td>
  <td class="age" data-sort="{{ageSort .TreeSizeAge}}">{{formatAge .TreeSizeAge}}</td>
  <td class="ctls">
    {{- if eq .State "running"}}
    <button type="button" class="ctl ctl-catchup" aria-label="Catch up" title="{{if $deny}}{{$deny}}{{else if isCatchupActive .CatchupUntil}}Catching up for {{catchupRemaining .CatchupUntil}} more{{else}}Catch up: faster fetching for 10 minutes{{end}}" onclick="logControl(this,'{{.URL}}','catchup')"{{if or $deny (isCatchupActive .CatchupUntil)}} disabled{{end}}><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M9.5 1 3 9h4.2L6.5 15 13 7H8.8z"/></svg></button>
    <button type="button" class="ctl ctl-pause" aria-label="Pause" title="{{or $deny "Pause: stop fetching now, resume later from the same place"}}" onclick="logControl(this,'{{.URL}}','pause')"{{if $deny}} disabled{{end}}><svg viewBox="0 0 16 16" aria-hidden="true"><rect x="3.5" y="2.5" width="3" height="11" rx="1"/><rect x="9.5" y="2.5" width="3" height="11" rx="1"/></svg></button>
    {{- else}}
    <button type="button" class="ctl ctl-resume" aria-label="Resume" title="{{or $deny "Resume ingestion from where it stopped"}}" onclick="logControl(this,'{{.URL}}','resume')"{{if $deny}} disabled{{end}}><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4.5 2.5v11l9-5.5z"/></svg></button>
    {{- end}}
    {{- if ne .State "stopped"}}
    <button type="button" class="ctl ctl-stop" aria-label="Stop" title="{{or $deny "Stop: halt ingestion and keep it halted across restarts"}}" onclick="logControl(this,'{{.URL}}','stop')"{{if $deny}} disabled{{end}}><svg viewBox="0 0 16 16" aria-hidden="true"><rect x="3" y="3" width="10" height="10" rx="1.5"/></svg></button>
    {{- end}}
  </td>
</tr>
{{end}}
</tbody>
</table>
</div>`

const logStatusPageHeader = `
<h1>CT Log Status</h1>
<p class="meta">
  Generated at <strong>{{.GeneratedAt}}</strong> &nbsp;·&nbsp;
  <strong>{{.TotalLogs}}</strong> logs monitored &nbsp;·&nbsp;
  Tree sizes refresh every 3 min &nbsp;·&nbsp; Page auto-refreshes every 2 min
</p>
`

// logStatusSortJS drives the sortable headers. logStatusControlJS is separate
// because /overview embeds the table and its sorting but reuses the same
// catch-up handler alongside it.
const logStatusSortJS = `
var SORT_KEY = 'ctLogStatusSort';

function cellValue(row, col) {
  var cell = row.cells[col];
  var raw = cell ? cell.getAttribute('data-sort') : null;
  if (raw === null) return '';
  var n = parseFloat(raw);
  return isNaN(n) ? raw.toLowerCase() : n;
}

function sortBy(col, dir) {
  var table = document.getElementById('logtable');
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);

  rows.sort(function (a, b) {
    var av = cellValue(a, col), bv = cellValue(b, col);
    if (av < bv) return -dir;
    if (av > bv) return dir;
    return 0;
  });

  // Re-appending an existing node moves it, so this reorders in place.
  rows.forEach(function (r) { tbody.appendChild(r); });

  table.querySelectorAll('th.sortable').forEach(function (th) {
    th.classList.remove('sort-asc', 'sort-desc');
    th.removeAttribute('aria-sort');
  });

  var active = table.querySelector('th[data-col="' + col + '"]');
  if (active) {
    active.classList.add(dir === 1 ? 'sort-asc' : 'sort-desc');
    active.setAttribute('aria-sort', dir === 1 ? 'ascending' : 'descending');
  }

  // The page reloads itself every two minutes; without this the sort would be
  // lost each time. Storage can be unavailable, so never let it break sorting.
  try { localStorage.setItem(SORT_KEY, col + ':' + dir); } catch (e) {}
}

document.querySelectorAll('#logtable th.sortable').forEach(function (th) {
  th.addEventListener('click', function () {
    var col = parseInt(th.dataset.col, 10);
    var dir;
    if (th.classList.contains('sort-asc')) {
      dir = -1;
    } else if (th.classList.contains('sort-desc')) {
      dir = 1;
    } else {
      // Numbers open descending — the interesting rows (most behind, largest)
      // are at the top. Names open ascending.
      dir = th.dataset.type === 'num' ? -1 : 1;
    }
    sortBy(col, dir);
  });
});

(function restoreSort() {
  var saved;
  try { saved = localStorage.getItem(SORT_KEY); } catch (e) { return; }
  if (!saved) return;

  var parts = saved.split(':');
  var col = parseInt(parts[0], 10), dir = parseInt(parts[1], 10);
  if (isNaN(col) || (dir !== 1 && dir !== -1)) return;
  if (!document.querySelector('#logtable th[data-col="' + col + '"]')) return;

  sortBy(col, dir);
})();

`

const logStatusControlJS = `function logControl(btn, url, action) {
  if (action === 'stop' && !confirm('Stop ingesting from this log?\n\nIt stays stopped, across restarts, until you resume it.')) {
    return;
  }
  var buttons = btn.closest('td').querySelectorAll('button.ctl');
  for (var i = 0; i < buttons.length; i++) { buttons[i].disabled = true; }
  var enable = function() {
    for (var i = 0; i < buttons.length; i++) { buttons[i].disabled = false; }
  };
  fetch('/log-status/control', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      // Required by the server: a cross-site page cannot send it.
      'X-Certstream-Control': '1'
    },
    body: 'url=' + encodeURIComponent(url) + '&action=' + encodeURIComponent(action)
  }).then(function(r) {
    if (r.ok) { location.reload(); return; }
    return r.text().then(function(t) { enable(); alert('Could not ' + action + ': ' + t.trim()); });
  }).catch(function() {
    enable();
    alert('Could not ' + action + ': the server could not be reached');
  });
}
`

// logStatusSectionCSS styles this page, shared with the combined /overview page.
const logStatusSectionCSS = `
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
.badge-proxy{background:#e0f2fe;color:#075985}
.eta-live{color:#15803d;font-weight:700}
.eta-good{color:#16a34a}
.eta-warn{color:#d97706}
.eta-bad{color:#dc2626;font-weight:600}
.eta-unknown{color:#9ca3af}
.status-live{color:#15803d}
.status-slight{color:#d97706}
.status-behind{color:#dc2626}
.age{color:#9ca3af}
th.sortable{cursor:pointer;user-select:none;position:relative;padding-right:22px}
th.sortable:hover{color:#fff;background:#273549}
th.sortable i{position:absolute;right:7px;top:50%;transform:translateY(-50%);font-style:normal;font-size:0.65rem;opacity:.3}
th.sortable i::after{content:"\2195"}
th.sortable.sort-asc i{opacity:1}
th.sortable.sort-asc i::after{content:"\25B2"}
th.sortable.sort-desc i{opacity:1}
th.sortable.sort-desc i::after{content:"\25BC"}
.badge-paused{background:#e0e7ff;color:#3730a3}
.badge-stopped{background:#fee2e2;color:#991b1b}
td.ctls{white-space:nowrap;text-align:right}
p.ctl-note{margin:0 0 12px;padding:8px 12px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0;color:#475569;font-size:0.8125rem}
p.ctl-note code{font-size:0.75rem;background:#eef2f7;padding:1px 5px;border-radius:4px}
button.ctl{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;margin-left:3px;padding:0;border:1px solid #d1d5db;border-radius:6px;background:#fff;color:#4b5563;cursor:pointer;vertical-align:middle}
button.ctl svg{width:14px;height:14px;fill:currentColor}
button.ctl:hover:not(:disabled){border-color:currentColor}
button.ctl:focus-visible{outline:2px solid #3b82f6;outline-offset:1px}
button.ctl-catchup:hover:not(:disabled){color:#ca8a04;background:#fefce8}
button.ctl-pause:hover:not(:disabled){color:#4338ca;background:#eef2ff}
button.ctl-resume{color:#15803d}
button.ctl-resume:hover:not(:disabled){background:#f0fdf4}
button.ctl-stop:hover:not(:disabled){color:#b91c1c;background:#fef2f2}
button.ctl:disabled{opacity:.4;cursor:not-allowed}
`

var logStatusTmpl = template.Must(template.New("logstatus").Funcs(logStatusFuncs()).
	Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="120">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CT Log Status</title>
<style>` + logStatusSectionCSS + `</style>
</head>
<body>` + logStatusPageHeader + logStatusTableMarkup +
		`<script>` + logStatusSortJS + logStatusControlJS + `</script>` + `</body>
</html>`))

// logStatusTableTmpl renders only the table, for embedding in /overview.
var logStatusTableTmpl = template.Must(template.New("logstatus-table").
	Funcs(logStatusFuncs()).Parse(logStatusTableMarkup))

type logStatusPageData struct {
	GeneratedAt string
	TotalLogs   int
	Logs        []certificatetransparency.LogStatusSnapshot

	// ControlsAllowed is whether this viewer may use the log controls;
	// ControlsConfigured whether anyone may. They decide whether the controls
	// render enabled, and what the tooltip says when they are not.
	ControlsAllowed    bool
	ControlsConfigured bool
	// ViewerIP is the address the server attributes this request to - what
	// belongs in allowed_ips. Behind a proxy without real_ip it is the proxy's,
	// which is exactly what an operator needs to notice.
	ViewerIP string
}

// catchupDuration is how long catch-up mode stays active after a trigger.
const catchupDuration = 10 * time.Minute

// catchupHandler is the original catch-up endpoint, kept for anything that
// calls it directly. It applies the same checks as controlHandler.
func catchupHandler(w http.ResponseWriter, r *http.Request) {
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

	if state := certificatetransparency.GetLogState(normURL); state != certificatetransparency.LogRunning {
		http.Error(w, fmt.Sprintf("log is %s; resume it first", state), http.StatusConflict)
		return
	}

	certificatetransparency.TriggerCatchup(normURL, catchupDuration)
	w.WriteHeader(http.StatusNoContent)
}

// buildLogStatusPageData gathers everything the page renders, split out so the
// combined /overview page can reuse it.
func buildLogStatusPageData(r *http.Request) logStatusPageData {

	logs := certificatetransparency.GetLogStatuses()

	data := logStatusPageData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		TotalLogs:   len(logs),
		Logs:        logs,

		ControlsAllowed:    controlsAllowedFor(r),
		ControlsConfigured: !controlAllowList().Empty(),
	}

	if r != nil {
		if ip := web.ClientIP(r); ip != nil {
			data.ViewerIP = ip.String()
		}
	}

	return data
}

func logStatusHandler(w http.ResponseWriter, r *http.Request) {
	data := buildLogStatusPageData(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := logStatusTmpl.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
