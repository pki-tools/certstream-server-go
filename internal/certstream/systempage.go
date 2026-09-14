package certstream

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

type queueView struct {
	Name    string
	Detail  string
	Depth   int64
	Cap     int64
	Percent float64
}

type systemPageData struct {
	GeneratedAt string
	Uptime      string
	Version     string
	GoVersion   string
	NumCPU      int

	Bottleneck Bottleneck
	Queues     []queueView

	RateNow   float64
	Processed int64
	Certs     int64
	Precerts  int64

	CPUPercent   float64
	GCPercent    float64
	CPUKnown     bool
	Goroutines   int
	HeapMB       float64
	GCCycles     uint32
	SamplesHeld  int
	WindowSecs   int
	RateSpark    []float64
	CPUSpark     []float64
	GoroutineMax int

	Clients      int
	ClientsFull  int64
	ClientsLite  int64
	ClientsDomn  int64
	Skipped      uint64
	LogsMonitor  int
	RateLimitHit int64
	ErrorCounts  []categoryCount
}

type categoryCount struct {
	Category string
	Count    int
}

var systemTmpl = template.Must(template.New("system").Funcs(template.FuncMap{
	"pct":  func(v float64) string { return fmt.Sprintf("%.1f%%", v) },
	"pct0": func(v float64) string { return fmt.Sprintf("%.0f%%", v) },
	"f1":   func(v float64) string { return fmt.Sprintf("%.1f", v) },
	// Accepts any integer kind: the page mixes int, int64, uint32 and uint64, and
	// a typed parameter would fail at execution time rather than compile time.
	"num": func(v any) string {
		var s string
		switch n := v.(type) {
		case int:
			s = strconv.Itoa(n)
		case int64:
			s = strconv.FormatInt(n, 10)
		case uint32:
			s = strconv.FormatUint(uint64(n), 10)
		case uint64:
			s = strconv.FormatUint(n, 10)
		default:
			s = fmt.Sprintf("%v", v)
		}

		var b strings.Builder
		off := len(s) % 3
		for i, c := range s {
			if i > 0 && (i-off)%3 == 0 {
				b.WriteByte(',')
			}
			b.WriteRune(c)
		}
		return b.String()
	},
	"rate": func(v float64) string {
		if v >= 100 {
			return fmt.Sprintf("%.0f", v)
		}
		if v >= 10 {
			return fmt.Sprintf("%.1f", v)
		}
		return fmt.Sprintf("%.2f", v)
	},
	// spark renders a sparkline as an SVG polyline scaled to the series maximum.
	"spark": func(vals []float64) template.HTML {
		if len(vals) < 2 {
			return ""
		}
		var max float64
		for _, v := range vals {
			if v > max {
				max = v
			}
		}
		if max <= 0 {
			max = 1
		}
		var b strings.Builder
		for i, v := range vals {
			x := float64(i) / float64(len(vals)-1) * 100
			y := 26 - (v/max)*24
			fmt.Fprintf(&b, "%.2f,%.2f ", x, y)
		}
		return template.HTML(`<svg class="spark" viewBox="0 0 100 28" preserveAspectRatio="none">` +
			`<polyline points="` + strings.TrimSpace(b.String()) + `"/></svg>`)
	},
	"barClass": func(p float64) string {
		switch {
		case p >= 75:
			return "q-hot"
		case p >= 40:
			return "q-warm"
		default:
			return "q-cool"
		}
	},
	"stageClass": func(stage string) string {
		switch stage {
		case "Broadcasting", "Entry handling":
			return "v-hot"
		case "Fetching":
			return "v-cool"
		default:
			return "v-idle"
		}
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="10">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System Stats</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:#f9f9f7;color:#0b0b0b;padding:24px 32px;min-height:100vh}
h1{font-size:1.375rem;font-weight:700;margin-bottom:4px}
h2{font-size:0.9375rem;font-weight:700;margin-bottom:2px}
.meta{font-size:0.8125rem;color:#52514e;margin-bottom:18px}
.meta strong{color:#0b0b0b}
.sub{font-size:0.75rem;color:#898781;margin-bottom:12px}
.card{background:#fff;border-radius:10px;padding:16px 18px;margin-bottom:14px;box-shadow:0 1px 3px rgba(11,11,11,.06),0 0 0 1px rgba(11,11,11,.05)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;margin-bottom:14px;align-items:start}

.verdict{border-radius:9px;padding:13px 16px;font-size:0.875rem;line-height:1.55;margin-bottom:14px}
.verdict b{font-weight:700}
.v-hot{background:#fff7ed;color:#7c2d12;box-shadow:inset 0 0 0 1px #fed7aa}
.v-cool{background:#eff6ff;color:#1e3a8a;box-shadow:inset 0 0 0 1px #bfdbfe}
.v-idle{background:#f8fafc;color:#475569;box-shadow:inset 0 0 0 1px #e2e8f0}

.split{display:flex;height:26px;border-radius:7px;overflow:hidden;margin:12px 0 6px;background:#f1f5f9}
.split div{display:flex;align-items:center;justify-content:center;font-size:0.6875rem;font-weight:700;color:#fff;white-space:nowrap;overflow:hidden}
.s-in{background:#2a78d6}
.s-out{background:#eb6834}
.s-busy{background:#1baf7a}
.splitkey{display:flex;gap:16px;flex-wrap:wrap;font-size:0.6875rem;color:#52514e}
.splitkey span{display:inline-flex;align-items:center;gap:6px}
.splitkey i{width:9px;height:9px;border-radius:2px}

.q{margin-bottom:14px}
.q:last-child{margin-bottom:0}
.q-head{display:flex;justify-content:space-between;font-size:0.8125rem;margin-bottom:5px}
.q-name{font-weight:600}
.q-val{font-variant-numeric:tabular-nums;color:#52514e}
.q-detail{font-size:0.6875rem;color:#898781;margin-top:4px}
.track{height:9px;border-radius:99px;background:#f1f5f9;overflow:hidden}
.track i{display:block;height:100%;border-radius:99px}
.q-cool i{background:#1baf7a}
.q-warm i{background:#eda100}
.q-hot i{background:#e34948}

.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:#fff;border-radius:10px;padding:13px 16px;box-shadow:0 1px 3px rgba(11,11,11,.06),0 0 0 1px rgba(11,11,11,.05)}
.stat-label{font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;color:#898781;font-weight:600}
.stat-value{font-size:1.5rem;font-weight:700;margin-top:3px;line-height:1.15}
.stat-sub{font-size:0.6875rem;color:#898781;margin-top:2px}
.spark{width:100%;height:28px;margin-top:6px;display:block}
.spark polyline{fill:none;stroke:#2a78d6;stroke-width:1.5;vector-effect:non-scaling-stroke}

table{width:100%;border-collapse:collapse;font-size:0.8125rem}
th{padding:7px 10px;text-align:left;color:#52514e;font-weight:600;font-size:0.6875rem;text-transform:uppercase;letter-spacing:.06em;background:#f9f9f7}
td{padding:7px 10px;border-top:1px solid #f0efec}
td.n{font-variant-numeric:tabular-nums;text-align:right}
a{color:#2a78d6}
@media(max-width:560px){body{padding:16px}.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>System Stats</h1>
<p class="meta">
  Generated <strong>{{.GeneratedAt}}</strong> &nbsp;·&nbsp;
  Up <strong>{{.Uptime}}</strong> &nbsp;·&nbsp;
  v{{.Version}} · {{.GoVersion}} · {{.NumCPU}} CPU &nbsp;·&nbsp;
  Refreshes every 10 s
</p>

<div class="card">
  <h2>Where the bottleneck is</h2>
  <p class="sub">Measured from how long the entry handler waits at each end of the pipeline, over the last {{.WindowSecs}} seconds</p>

  <div class="verdict {{stageClass .Bottleneck.Stage}}">
    <b>{{.Bottleneck.Stage}}.</b> {{.Bottleneck.Detail}}
  </div>

  {{if .Bottleneck.Known}}
  <div class="split">
    {{if gt .Bottleneck.WaitIn 6.0}}<div class="s-in" style="width:{{pct .Bottleneck.WaitIn}}">{{pct0 .Bottleneck.WaitIn}}</div>{{end}}
    {{if gt .Bottleneck.WaitOut 6.0}}<div class="s-out" style="width:{{pct .Bottleneck.WaitOut}}">{{pct0 .Bottleneck.WaitOut}}</div>{{end}}
    {{if gt .Bottleneck.Busy 6.0}}<div class="s-busy" style="width:{{pct .Bottleneck.Busy}}">{{pct0 .Bottleneck.Busy}}</div>{{end}}
  </div>
  <div class="splitkey">
    <span><i style="background:#2a78d6"></i>Waiting for certificates ({{pct .Bottleneck.WaitIn}})</span>
    <span><i style="background:#eb6834"></i>Blocked sending downstream ({{pct .Bottleneck.WaitOut}})</span>
    <span><i style="background:#1baf7a"></i>Own work ({{pct .Bottleneck.Busy}})</span>
  </div>
  {{end}}
</div>

<div class="grid">
  <div class="card">
    <h2>Queues</h2>
    <p class="sub">A queue near capacity is where the pipeline is backing up</p>
    {{range .Queues}}
    <div class="q {{barClass .Percent}}">
      <div class="q-head"><span class="q-name">{{.Name}}</span><span class="q-val">{{num .Depth}} / {{num .Cap}} · {{pct0 .Percent}}</span></div>
      <div class="track"><i style="width:{{pct .Percent}}"></i></div>
      <div class="q-detail">{{.Detail}}</div>
    </div>
    {{end}}
  </div>

  <div class="card">
    <h2>Recent errors</h2>
    <p class="sub">Categories in the sliding window — see <a href="/errors">/errors</a> for detail</p>
    {{if .ErrorCounts}}
    <table>
      <thead><tr><th>Category</th><th style="text-align:right">Count</th></tr></thead>
      <tbody>
      {{range .ErrorCounts}}<tr><td>{{.Category}}</td><td class="n">{{.Count}}</td></tr>{{end}}
      </tbody>
    </table>
    {{else}}
    <p class="sub" style="margin:10px 0 0">No errors recorded.</p>
    {{end}}
  </div>
</div>

<div class="stat-row">
  <div class="stat">
    <div class="stat-label">Throughput</div>
    <div class="stat-value">{{rate .RateNow}}</div>
    <div class="stat-sub">certificates/sec</div>
    {{spark .RateSpark}}
  </div>
  <div class="stat">
    <div class="stat-label">CPU</div>
    <div class="stat-value">{{if .CPUKnown}}{{pct0 .CPUPercent}}{{else}}—{{end}}</div>
    <div class="stat-sub">{{if .CPUKnown}}of one core · {{pct .GCPercent}} in GC{{else}}not reported on this platform{{end}}</div>
    {{if .CPUKnown}}{{spark .CPUSpark}}{{end}}
  </div>
  <div class="stat">
    <div class="stat-label">Goroutines</div>
    <div class="stat-value">{{.Goroutines}}</div>
    <div class="stat-sub">peak {{.GoroutineMax}} in window</div>
  </div>
  <div class="stat">
    <div class="stat-label">Heap in use</div>
    <div class="stat-value">{{f1 .HeapMB}}</div>
    <div class="stat-sub">MB · {{.GCCycles}} GC cycles</div>
  </div>
  <div class="stat">
    <div class="stat-label">Processed</div>
    <div class="stat-value">{{num .Processed}}</div>
    <div class="stat-sub">{{num .Certs}} certs · {{num .Precerts}} precerts</div>
  </div>
  <div class="stat">
    <div class="stat-label">Clients</div>
    <div class="stat-value">{{.Clients}}</div>
    <div class="stat-sub">{{.ClientsFull}} full · {{.ClientsLite}} lite · {{.ClientsDomn}} domains</div>
  </div>
  <div class="stat">
    <div class="stat-label">Skipped</div>
    <div class="stat-value">{{num .Skipped}}</div>
    <div class="stat-sub">dropped for slow clients</div>
  </div>
  <div class="stat">
    <div class="stat-label">Throttled</div>
    <div class="stat-value">{{num .RateLimitHit}}</div>
    <div class="stat-sub">429/503 from log operators</div>
  </div>
</div>
</body>
</html>`))

func systemHandler(w http.ResponseWriter, _ *http.Request) {
	samples := snapshotSamples()

	cpu, gc, cpuKnown := cpuPercentOver(samples)

	data := systemPageData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Uptime:      formatUptime(time.Since(startedAt)),
		Version:     config.Version,
		GoVersion:   runtime.Version(),
		NumCPU:      runtime.NumCPU(),
		Bottleneck:  classifyBottleneck(samples),
		RateNow:     rateOver(samples),
		Certs:       certificatetransparency.GetProcessedCerts(),
		Precerts:    certificatetransparency.GetProcessedPrecerts(),
		CPUPercent:  cpu,
		GCPercent:   gc,
		CPUKnown:    cpuKnown,
		Goroutines:  runtime.NumGoroutine(),
		SamplesHeld: len(samples),
		WindowSecs:  int(float64(len(samples)) * statsInterval.Seconds()),

		Clients:      web.ClientHandler.ClientCount(),
		ClientsFull:  web.ClientHandler.ClientFullCount(),
		ClientsLite:  web.ClientHandler.ClientLiteCount(),
		ClientsDomn:  web.ClientHandler.ClientDomainsCount(),
		Skipped:      web.ClientHandler.TotalSkippedCerts(),
		LogsMonitor:  certificatetransparency.CountMonitoredLogs(),
		RateLimitHit: certificatetransparency.TotalRateLimitHits(),
	}

	data.Processed = data.Certs + data.Precerts

	if n := len(samples); n > 0 {
		last := samples[n-1]
		data.HeapMB = float64(last.HeapBytes) / (1024 * 1024)
		data.GCCycles = last.GCCycles

		data.Queues = []queueView{
			{
				Name:   "Entry channel",
				Detail: "Fetch workers to the entry handler (buffer_sizes.certchan). Full means the handler cannot keep up with downloads.",
				Depth:  last.CertChanDepth, Cap: last.CertChanCap,
				Percent: percentOf(last.CertChanDepth, last.CertChanCap),
			},
			{
				Name:   "Broadcast channel",
				Detail: "Entry handler to the broadcaster (buffer_sizes.broadcastmanager). Full means JSON encoding and client fan-out cannot keep up.",
				Depth:  int64(last.BroadcastDepth), Cap: int64(last.BroadcastCap),
				Percent: percentOf(int64(last.BroadcastDepth), int64(last.BroadcastCap)),
			},
		}
	}

	for _, s := range samples {
		if s.Goroutines > data.GoroutineMax {
			data.GoroutineMax = s.Goroutines
		}
	}

	data.RateSpark, data.CPUSpark = buildSparks(samples)
	data.ErrorCounts = errorCategoryCounts()

	// Render into a buffer first. Executing straight to the ResponseWriter commits
	// a 200 and partial HTML before any failure surfaces, which looks like a
	// successful response carrying a half-drawn page.
	var buf bytes.Buffer
	if err := systemTmpl.Execute(&buf, data); err != nil {
		log.Printf("system page: template error: %v\n", err)
		http.Error(w, "template error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	if _, err := buf.WriteTo(w); err != nil {
		log.Printf("system page: write failed: %v\n", err)
	}
}

// buildSparks derives per-interval rate and CPU series from the cumulative counters.
func buildSparks(samples []statSample) (rates, cpus []float64) {
	for i := 1; i < len(samples); i++ {
		prev, cur := samples[i-1], samples[i]

		elapsed := cur.At.Sub(prev.At).Seconds()
		if elapsed <= 0 {
			continue
		}

		if d := cur.Processed - prev.Processed; d >= 0 {
			rates = append(rates, float64(d)/elapsed)
		}

		cpus = append(cpus, (cur.CPUSeconds-prev.CPUSeconds)/elapsed*100)
	}

	return rates, cpus
}

func percentOf(depth, capacity int64) float64 {
	if capacity <= 0 {
		return 0
	}

	return float64(depth) / float64(capacity) * 100
}

// errorCategoryCounts tallies the error ring by category, worst first.
func errorCategoryCounts() []categoryCount {
	counts := make(map[string]int)
	for _, r := range certificatetransparency.GetRecentErrors(0) {
		counts[string(r.Category)]++
	}

	out := make([]categoryCount, 0, len(counts))
	for cat, n := range counts {
		out = append(out, categoryCount{Category: cat, Count: n})
	}

	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Count > out[j-1].Count; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}

	return out
}

func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm %ds", mins, int(d.Seconds())%60)
	}
}
