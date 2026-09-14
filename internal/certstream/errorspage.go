package certstream

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
)

var errorsTmpl = template.Must(template.New("errors").Funcs(template.FuncMap{
	"formatTime": func(t time.Time) string {
		return t.UTC().Format("2006-01-02 15:04:05")
	},
	"formatAge": func(t time.Time) string {
		d := time.Since(t).Round(time.Second)
		switch {
		case d < time.Minute:
			return fmt.Sprintf("%ds ago", int(d.Seconds()))
		case d < time.Hour:
			m := int(d.Minutes())
			s := int(d.Seconds()) % 60
			if s == 0 {
				return fmt.Sprintf("%dm ago", m)
			}
			return fmt.Sprintf("%dm %ds ago", m, s)
		default:
			h := int(d.Hours())
			m := int(d.Minutes()) % 60
			if m == 0 {
				return fmt.Sprintf("%dh ago", h)
			}
			return fmt.Sprintf("%dh %dm ago", h, m)
		}
	},
	"sharePct": func(v, max int64) int {
		if max <= 0 {
			return 0
		}
		pct := int(v * 100 / max)
		if pct < 3 {
			return 3 // keep a sliver visible for very small counts
		}
		return pct
	},
	"catClass": func(cat certificatetransparency.ErrorCategory) string {
		switch cat {
		case certificatetransparency.ErrCatConnection:
			return "cat-conn"
		case certificatetransparency.ErrCatSTH:
			return "cat-sth"
		case certificatetransparency.ErrCatCheckpoint:
			return "cat-checkpoint"
		case certificatetransparency.ErrCatParse:
			return "cat-parse"
		case certificatetransparency.ErrCatScan:
			return "cat-scan"
		case certificatetransparency.ErrCatTreeSize:
			return "cat-treesize"
		case certificatetransparency.ErrCatCCADB:
			return "cat-ccadb"
		case certificatetransparency.ErrCatRateLimit:
			return "cat-ratelimit"
		case certificatetransparency.ErrCatBackfill:
			return "cat-backfill"
		case certificatetransparency.ErrCatTile:
			return "cat-tile"
		default:
			return "cat-other"
		}
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="30">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CT Log Errors</title>
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
.empty{background:#fff;border-radius:10px;padding:48px;text-align:center;color:#6b7280;font-size:0.9rem;box-shadow:0 1px 4px rgba(0,0,0,.12)}
input[type=search]{width:100%;padding:8px 14px;border:1px solid #e2e8f0;border-radius:8px;font-size:0.875rem;margin-bottom:14px;outline:none;background:#fff}
input[type=search]:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.15)}
.wrap{overflow-x:auto;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.12),0 0 0 1px rgba(0,0,0,.05)}
table{width:100%;border-collapse:collapse;background:#fff;font-size:0.8125rem}
thead tr{background:#1e293b}
th{padding:10px 14px;text-align:left;color:#cbd5e1;font-weight:600;font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
td{padding:9px 14px;border-bottom:1px solid #f1f5f9;vertical-align:top;word-break:break-word}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#f8fafc}
.age{color:#9ca3af;white-space:nowrap}
.ts{font-variant-numeric:tabular-nums;font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:0.75rem;color:#6b7280;white-space:nowrap}
.logname{font-weight:500;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msg{max-width:520px;font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:0.75rem;color:#374151}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:0.6875rem;font-weight:600;letter-spacing:.02em;white-space:nowrap}
.cat-conn       {background:#fee2e2;color:#991b1b}
.cat-sth        {background:#fef3c7;color:#92400e}
.cat-checkpoint {background:#fef3c7;color:#92400e}
.cat-parse      {background:#ede9fe;color:#5b21b6}
.cat-scan       {background:#ffedd5;color:#9a3412}
.cat-treesize   {background:#e0f2fe;color:#075985}
.cat-ccadb      {background:#dcfce7;color:#166534}
.cat-ratelimit  {background:#fee2e2;color:#b91c1c;box-shadow:inset 0 0 0 1px #fca5a5}
.cat-backfill   {background:#e0e7ff;color:#3730a3}
.cat-tile       {background:#fef3c7;color:#92400e}
.cat-other      {background:#f1f5f9;color:#475569}

.diag{background:#fff;border-radius:10px;padding:15px 18px;margin-bottom:18px;box-shadow:0 1px 4px rgba(0,0,0,.12),0 0 0 1px rgba(0,0,0,.05)}
.diag h2{font-size:0.9375rem;font-weight:700;margin-bottom:2px}
.diag .hint{font-size:0.75rem;color:#6b7280;margin-bottom:12px}
.diag table{margin-top:2px}
.verdict{border-radius:8px;padding:10px 13px;font-size:0.8125rem;line-height:1.5;margin-bottom:12px}
.verdict b{font-weight:700}
.v-rl{background:#fef2f2;color:#7f1d1d;box-shadow:inset 0 0 0 1px #fecaca}
.v-sat{background:#fff7ed;color:#7c2d12;box-shadow:inset 0 0 0 1px #fed7aa}
.v-ok{background:#f0fdf4;color:#14532d;box-shadow:inset 0 0 0 1px #bbf7d0}
.v-bf{background:#eef2ff;color:#312e81;box-shadow:inset 0 0 0 1px #c7d2fe}
.bar{position:relative;height:7px;border-radius:99px;background:#f1f5f9;overflow:hidden;min-width:90px}
.bar i{position:absolute;left:0;top:0;bottom:0;border-radius:99px;background:#dc2626}
</style>
</head>
<body>
<h1>CT Log Errors</h1>
<p class="meta">
  Generated at <strong>{{.GeneratedAt}}</strong> &nbsp;·&nbsp;
  Sliding window: last <strong>{{.WindowSize}}</strong> errors &nbsp;·&nbsp;
  Page auto-refreshes every 30 s
</p>
<div class="diag">
  <h2>Throughput diagnosis</h2>
  <p class="hint">Why a log falls behind: it is being throttled by the operator, or this server cannot drain what it already fetches.</p>

  {{if .Backfilling}}
  <div class="verdict v-bf">
    <b>{{.Backfilling}} log{{if ne .Backfilling 1}}s are{{else}} is{{end}} backfilling from index 0.</b>
    These had no saved position and <code>recovery.start_at_head</code> is disabled, so they are downloading the log's entire history.
    On <code>/log-status</code> that is indistinguishable from falling behind, but it is a cold start working through a fixed backlog — the estimate shrinks as it catches up.
    To start these live instead, set <code>recovery.start_at_head: true</code> and restart.
  </div>
  {{end}}

  {{if .RateLimits}}
  <div class="verdict v-rl">
    <b>Rate limiting detected.</b> {{.TotalRateLimitHits}} throttled response{{if ne .TotalRateLimitHits 1}}s{{end}} across {{len .RateLimits}} log{{if ne (len .RateLimits) 1}}s{{end}}.
    The CT client retries these automatically with backoff, so they never surface as scan failures — the log just silently falls behind.
    <b>Raising <code>parallel_fetch</code> or using Catch Up on these logs makes it worse</b>, since more concurrent requests earn more throttling. Lower <code>parallel_fetch</code> for them instead.
  </div>
  {{else if .PipelineSaturated}}
  <div class="verdict v-sat">
    <b>No rate limiting seen, but the pipeline is backed up</b> ({{.PipelineDepth}} of {{.PipelineCap}} entries queued).
    Fetching is outpacing processing, so the bottleneck is downstream — CPU, JSON encoding, or slow WebSocket clients. More fetch connections will not help; raise <code>buffer_sizes.certchan</code> and check CPU headroom.
  </div>
  {{else}}
  <div class="verdict v-ok">
    <b>No rate limiting seen{{if gt .PipelineCap 0}} and the pipeline is keeping up</b> ({{.PipelineDepth}} of {{.PipelineCap}} entries queued){{else}}</b>{{end}}.
    If logs are still behind, the fetch rate is simply too low — raise <code>scanner.batch_size</code> toward 1000 and <code>parallel_fetch</code> to 2–3, then watch this page for throttling appearing.
  </div>
  {{end}}

  {{if .RateLimits}}
  <div class="wrap"><table>
  <thead><tr><th>Log</th><th>Throttled responses</th><th>Share</th><th>Last status</th><th>Retry-After</th><th>Last seen</th></tr></thead>
  <tbody>
  {{range .RateLimits}}
  <tr>
    <td class="logname" title="{{.LogURL}}">{{if .LogName}}{{.LogName}}{{else}}{{.LogURL}}{{end}}</td>
    <td class="ts">{{.Count}}</td>
    <td><div class="bar"><i style="width:{{sharePct .Count $.MaxRateLimit}}%"></i></div></td>
    <td class="ts">{{.LastStatus}}</td>
    <td class="ts">{{if .RetryAfter}}{{.RetryAfter}}{{else}}—{{end}}</td>
    <td class="age">{{formatAge .LastAt}}</td>
  </tr>
  {{end}}
  </tbody>
  </table></div>
  {{end}}
</div>

{{if .Errors}}
<div class="stat-row">
  <div class="stat"><div class="stat-label">Errors stored</div><div class="stat-value">{{.Total}}</div></div>
  {{if .MostRecentAge}}<div class="stat"><div class="stat-label">Most recent</div><div class="stat-value" style="font-size:1rem;padding-top:4px">{{.MostRecentAge}}</div></div>{{end}}
</div>
<input type="search" id="q" placeholder="Filter by log name, category or message…" oninput="filterTable(this.value)">
<div class="wrap">
<table id="tbl">
<thead>
<tr>
  <th>Time (UTC)</th>
  <th>Age</th>
  <th>Log</th>
  <th>Category</th>
  <th>Message</th>
</tr>
</thead>
<tbody>
{{range .Errors}}
<tr>
  <td class="ts">{{formatTime .Time}}</td>
  <td class="age">{{formatAge .Time}}</td>
  <td class="logname" title="{{.LogURL}}">{{if .LogName}}{{.LogName}}{{else}}{{.LogURL}}{{end}}</td>
  <td><span class="badge {{catClass .Category}}">{{.Category}}</span></td>
  <td class="msg">{{.Message}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{else}}
<div class="empty">No errors recorded yet — all logs appear healthy.</div>
{{end}}
<script>
function filterTable(q){
  q=q.toLowerCase();
  var rows=document.querySelectorAll('#tbl tbody tr');
  rows.forEach(function(r){
    if(!q){r.hidden=false;return;}
    var text=r.cells[2].textContent+' '+r.cells[3].textContent+' '+r.cells[4].textContent;
    r.hidden=!text.toLowerCase().includes(q);
  });
}
</script>
</body>
</html>`))

type errorsPageData struct {
	GeneratedAt   string
	WindowSize    int
	Total         int
	MostRecentAge string
	Errors        []certificatetransparency.ErrorRecord

	RateLimits         []certificatetransparency.RateLimitStat
	TotalRateLimitHits int64
	MaxRateLimit       int64
	PipelineDepth      int64
	PipelineCap        int64
	PipelineSaturated  bool
	Backfilling        int
}

func errorsHandler(w http.ResponseWriter, _ *http.Request) {
	const maxDisplay = 500
	records := certificatetransparency.GetRecentErrors(maxDisplay)
	total := certificatetransparency.ErrorRingSize()

	var mostRecentAge string
	if len(records) > 0 {
		d := time.Since(records[0].Time).Round(time.Second)
		switch {
		case d < time.Minute:
			mostRecentAge = fmt.Sprintf("%ds ago", int(d.Seconds()))
		case d < time.Hour:
			mostRecentAge = fmt.Sprintf("%dm ago", int(d.Minutes()))
		default:
			mostRecentAge = fmt.Sprintf("%dh ago", int(d.Hours()))
		}
	}

	rateLimits := certificatetransparency.GetRateLimitStats()
	depth, capacity := certificatetransparency.GetPipelineDepth()

	var maxRL int64
	if len(rateLimits) > 0 {
		maxRL = rateLimits[0].Count // GetRateLimitStats sorts worst-first
	}

	data := errorsPageData{
		GeneratedAt:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		WindowSize:    maxDisplay,
		Total:         total,
		MostRecentAge: mostRecentAge,
		Errors:        records,

		RateLimits:         rateLimits,
		TotalRateLimitHits: certificatetransparency.TotalRateLimitHits(),
		MaxRateLimit:       maxRL,
		PipelineDepth:      depth,
		PipelineCap:        capacity,
		// Over half full means fetching is outrunning downstream processing.
		PipelineSaturated: capacity > 0 && depth*2 > capacity,
		Backfilling:       certificatetransparency.BackfillingLogs(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := errorsTmpl.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
