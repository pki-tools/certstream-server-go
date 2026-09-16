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
{{range .Logs}}
<tr>
  <td data-sort="{{.Operator}}">{{.Operator}}</td>
  <td data-sort="{{.Name}}">{{.Name}}</td>
  <td data-sort="{{.Type}}">
    <span class="badge {{typeClass .Type}}">{{.Type}}</span>
    {{if isCatchupActive .CatchupUntil}}<span class="badge badge-catchup" title="Catch-up active for {{catchupRemaining .CatchupUntil}} more">&#9889; {{catchupRemaining .CatchupUntil}}</span>{{end}}
    {{if .Proxy}}<span class="badge badge-proxy" title="Fetched via egress proxy {{.Proxy}}">&#8644; {{.Proxy}}</span>{{end}}
  </td>
  <td class="num" data-sort="{{.CurrentIndex}}">{{formatNumber .CurrentIndex}}</td>
  <td class="num" data-sort="{{.TreeSize}}">{{if gt .TreeSize 0}}{{formatNumber .TreeSize}}{{else}}<span class="age">Pending</span>{{end}}</td>
  <td class="num {{behindClass .Behind}}" data-sort="{{.Behind}}">{{if gt .TreeSize 0}}{{if eq .Behind 0}}—{{else}}{{formatNumber .Behind}}{{end}}{{else}}<span class="age">—</span>{{end}}</td>
  <td class="num" data-sort="{{.RatePerSec}}">{{if gt .RatePerSec 0.0}}{{formatRate .RatePerSec}}{{else}}<span class="age">—</span>{{end}}</td>
  <td class="{{etaClass .ETA}}" data-sort="{{etaSort .ETA .Behind}}">{{formatETA .ETA .Behind}}</td>
  <td class="age" data-sort="{{ageSort .TreeSizeAge}}">{{formatAge .TreeSizeAge}}</td>
  <td><button class="catchup-btn" onclick="triggerCatchup(this,'{{.URL}}')" {{if isCatchupActive .CatchupUntil}}disabled{{end}}>{{if isCatchupActive .CatchupUntil}}Catching up…{{else}}Catch Up{{end}}</button></td>
</tr>
{{end}}
</tbody>
</table>
</div>
<script>
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
