package certstream

import (
	"html/template"
	"net/http"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
)

var ccadbTmpl = template.Must(template.New("ccadb").Funcs(template.FuncMap{
	"formatTime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"formatTimeSince": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		d := time.Since(t).Round(time.Second)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return formatMinSec(d)
		case d < 24*time.Hour:
			return formatHourMin(d)
		default:
			h := int(d.Hours())
			return formatDays(h)
		}
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="300">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CCADB CA Owners</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1a1a1a;padding:24px 32px;min-height:100vh}
h1{font-size:1.375rem;font-weight:700;margin-bottom:4px;letter-spacing:-0.01em}
.meta{font-size:0.8125rem;color:#6b7280;margin-bottom:20px}
.meta strong{color:#374151}
.stat-row{display:flex;gap:24px;margin-bottom:20px;flex-wrap:wrap}
.stat{background:#fff;border-radius:8px;padding:12px 20px;box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:140px}
.stat-label{font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;font-weight:600}
.stat-value{font-size:1.5rem;font-weight:700;color:#1e293b;margin-top:2px;font-variant-numeric:tabular-nums}
.wrap{overflow-x:auto;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.12),0 0 0 1px rgba(0,0,0,.05)}
table{width:100%;border-collapse:collapse;background:#fff;font-size:0.8125rem}
thead tr{background:#1e293b}
th{padding:10px 14px;text-align:left;color:#cbd5e1;font-weight:600;font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
td{padding:9px 14px;border-bottom:1px solid #f1f5f9;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#f8fafc}
.num{font-variant-numeric:tabular-nums;font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:0.8rem;text-align:right}
.th-num{text-align:right}
.age{color:#9ca3af}
input[type=search]{width:100%;padding:8px 14px;border:1px solid #e2e8f0;border-radius:8px;font-size:0.875rem;margin-bottom:14px;outline:none;background:#fff}
input[type=search]:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.15)}
</style>
</head>
<body>
<h1>CCADB CA Owners</h1>
<p class="meta">
  Generated at <strong>{{formatTime .GeneratedAt}}</strong> &nbsp;·&nbsp;
  Last CCADB refresh: <strong>{{if .LastRefreshed.IsZero}}never{{else}}{{formatTime .LastRefreshed}} ({{formatTimeSince .LastRefreshed}}){{end}}</strong> &nbsp;·&nbsp;
  Page auto-refreshes every 5 min
</p>
<div class="stat-row">
  <div class="stat"><div class="stat-label">Total CAs</div><div class="stat-value">{{.TotalCAs}}</div></div>
  <div class="stat"><div class="stat-label">CA Owners</div><div class="stat-value">{{.TotalOwners}}</div></div>
</div>
<input type="search" id="q" placeholder="Filter by owner name…" oninput="filterTable(this.value)">
<div class="wrap">
<table id="tbl">
<thead>
<tr>
  <th>CA Owner</th>
  <th class="th-num"># CAs</th>
  <th>First Seen</th>
  <th>First Seen (relative)</th>
</tr>
</thead>
<tbody>
{{range .Owners}}
<tr>
  <td>{{.Owner}}</td>
  <td class="num">{{.CACount}}</td>
  <td class="age">{{formatTime .FirstSeen}}</td>
  <td class="age">{{formatTimeSince .FirstSeen}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
<script>
function filterTable(q){
  q=q.toLowerCase();
  var rows=document.querySelectorAll('#tbl tbody tr');
  rows.forEach(function(r){
    r.hidden=q&&!r.cells[0].textContent.toLowerCase().includes(q);
  });
}
</script>
</body>
</html>`))

type ccadbPageData struct {
	GeneratedAt   time.Time
	LastRefreshed time.Time
	TotalCAs      int
	TotalOwners   int
	Owners        []certificatetransparency.CCADBOwnerSnapshot
}

func ccadbHandler(w http.ResponseWriter, _ *http.Request) {
	status := certificatetransparency.GetCCADBStatus()

	data := ccadbPageData{
		GeneratedAt:   time.Now().UTC(),
		LastRefreshed: status.LastRefreshed,
		TotalCAs:      status.TotalCAs,
		TotalOwners:   status.TotalOwners,
		Owners:        status.Owners,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ccadbTmpl.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// helper funcs used in the template FuncMap (defined here to avoid init-order issues)
func formatMinSec(d time.Duration) string {
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if s == 0 {
		return formatPlural(m, "minute")
	}
	return formatPlural(m, "minute") + " " + formatPlural(s, "second")
}

func formatHourMin(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if m == 0 {
		return formatPlural(h, "hour")
	}
	return formatPlural(h, "hour") + " " + formatPlural(m, "minute")
}

func formatDays(hours int) string {
	d := hours / 24
	h := hours % 24
	if h == 0 {
		return formatPlural(d, "day")
	}
	return formatPlural(d, "day") + " " + formatPlural(h, "hour")
}

func formatPlural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return itoa(n) + " " + unit + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
