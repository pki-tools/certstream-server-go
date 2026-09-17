package certstream

import (
	"bytes"
	"html/template"
	"log"
	"net/http"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
)

// The combined page renders each section with that section's own template and
// splices the results in. Merging their FuncMaps is not an option: the log and
// error pages both define formatAge with different parameter types, so one would
// silently shadow the other.
type overviewPageData struct {
	Version   string
	Uptime    string
	GoVersion string
	NumCPU    int
	TotalLogs int
	WindowSze int
	Proxies   []string

	DashboardEnabled bool

	SystemSection template.HTML
	LogsSection   template.HTML
	ErrorsSection template.HTML
}

var overviewTmpl = template.Must(template.New("overview").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>certstream overview</title>
<style>
` + dashboardCSS + `
` + systemSectionCSS + `
` + logStatusSectionCSS + `
` + errorsSectionCSS + `

/* Overview shell: sticky section nav above stacked sections. */
body{padding:0;background:#f9f9f7}
.topbar{position:sticky;top:0;z-index:20;background:rgba(249,249,247,.94);backdrop-filter:blur(8px);
        border-bottom:1px solid #e1e0d9;padding:9px 20px}
.topbar-inner{display:flex;align-items:center;gap:12px;flex-wrap:wrap;max-width:1700px;margin:0 auto}
.brand{font-size:0.9375rem;font-weight:700;white-space:nowrap}
.brand span{font-weight:400;color:#898781;font-size:0.75rem;margin-left:6px}
.navlinks{display:flex;gap:3px;flex-wrap:wrap;margin-left:auto}
.navlinks a{font-size:0.75rem;font-weight:600;color:#52514e;text-decoration:none;
            padding:5px 11px;border-radius:7px;border:1px solid transparent;white-space:nowrap}
.navlinks a:hover{background:#fff;border-color:#e1e0d9}
main{max-width:1700px;margin:0 auto;padding:18px 20px 40px}
section{scroll-margin-top:62px;margin-bottom:30px}
.sec-head{display:flex;align-items:baseline;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.sec-head h1{font-size:1.125rem;font-weight:700;margin:0}
.sec-head .sec-note{font-size:0.75rem;color:#898781}
.sec-head a.more{font-size:0.6875rem;color:#2a78d6;text-decoration:none;margin-left:auto;white-space:nowrap}

/* The log table is inherently wide; scroll it inside its card, not the page. */
.logwrap{overflow-x:auto;border-radius:9px}
.logwrap table{min-width:820px}

@media(max-width:700px){
  .topbar{padding:8px 12px}
  .navlinks{margin-left:0;width:100%}
  main{padding:14px 12px 30px}
  .grid{grid-template-columns:1fr}
  .stat-row{grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:8px}
  .stat{padding:10px 12px}
  .stat-value{font-size:1.25rem}
  .stat-value.is-small,.stat-value.is-text{font-size:1rem}
  section{margin-bottom:22px}
  .sec-head a.more{margin-left:0}
}
</style>
</head>
<body>

<div class="topbar"><div class="topbar-inner">
  <div class="brand">certstream <span>v{{.Version}} · up {{.Uptime}}</span></div>
  <nav class="navlinks">
    <a href="#system">System</a>
    {{if .DashboardEnabled}}<a href="#charts">Trends</a>{{end}}
    <a href="#logs">Logs</a>
    <a href="#errors">Errors</a>
    <a href="/ccadb">CCADB</a>
  </nav>
</div></div>

<main>

<section id="system">
  <div class="sec-head">
    <h1>System</h1>
    <span class="sec-note">{{.NumCPU}} CPU · {{.GoVersion}}</span>
    <a class="more" href="/system">full page →</a>
  </div>
  {{.SystemSection}}
</section>

{{if .DashboardEnabled}}
<section id="charts">
  <div class="sec-head">
    <h1>Trends</h1>
    <span class="sec-note">History from the dashboard database</span>
    <a class="more" href="/dashboard">full page →</a>
  </div>
` + dashboardBody + `
</section>
{{end}}

<section id="logs">
  <div class="sec-head">
    <h1>Logs</h1>
    <span class="sec-note">{{.TotalLogs}} monitored{{if .Proxies}} · {{len .Proxies}} egress prox{{if eq (len .Proxies) 1}}y{{else}}ies{{end}}{{end}} · tap a header to sort</span>
    <a class="more" href="/log-status">full page →</a>
  </div>
  <div class="card"><div class="logwrap">{{.LogsSection}}</div></div>
</section>

<section id="errors">
  <div class="sec-head">
    <h1>Errors</h1>
    <span class="sec-note">Most recent {{.WindowSze}} across all logs</span>
    <a class="more" href="/errors">full page →</a>
  </div>
  {{.ErrorsSection}}
</section>

</main>

{{if .DashboardEnabled}}
<script>` + dashboardJS + `</script>
{{end}}
<script>
` + logStatusSortJS + `
` + logStatusCatchupJS + `

// Refresh without losing scroll position, which a meta refresh would discard
// on a page this long. The sort itself is already persisted separately.
(function () {
  var KEY = 'ctOverviewScroll';

  try {
    var y = sessionStorage.getItem(KEY);
    if (y !== null) {
      window.scrollTo(0, parseInt(y, 10) || 0);
      sessionStorage.removeItem(KEY);
    }
  } catch (e) {}

  setTimeout(function () {
    try { sessionStorage.setItem(KEY, String(window.scrollY)); } catch (e) {}
    location.reload();
  }, 30000);
})();
</script>
</body>
</html>`))

// renderSection executes one section template into HTML for splicing.
func renderSection(t *template.Template, data any) (template.HTML, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}

	return template.HTML(buf.String()), nil //nolint:gosec // our own template output
}

func overviewHandler(w http.ResponseWriter, _ *http.Request) {
	sys := buildSystemPageData()
	logs := buildLogStatusPageData()
	errs := buildErrorsPageData()

	data := overviewPageData{
		Version:          sys.Version,
		Uptime:           sys.Uptime,
		GoVersion:        sys.GoVersion,
		NumCPU:           sys.NumCPU,
		TotalLogs:        logs.TotalLogs,
		WindowSze:        errs.WindowSize,
		Proxies:          certificatetransparency.ProxyNames(),
		DashboardEnabled: dashboardStore != nil,
	}

	var err error
	if data.SystemSection, err = renderSection(systemSectionTmpl, sys); err != nil {
		overviewFailed(w, "system", err)
		return
	}

	if data.LogsSection, err = renderSection(logStatusTableTmpl, logs); err != nil {
		overviewFailed(w, "logs", err)
		return
	}

	if data.ErrorsSection, err = renderSection(errorsSectionTmpl, errs); err != nil {
		overviewFailed(w, "errors", err)
		return
	}

	// Buffered so a template failure yields a clean 500 rather than a page that
	// stops halfway with a 200 already sent.
	var buf bytes.Buffer
	if err := overviewTmpl.Execute(&buf, data); err != nil {
		overviewFailed(w, "shell", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	if _, err := buf.WriteTo(w); err != nil {
		log.Printf("overview page: write failed: %v\n", err)
	}
}

func overviewFailed(w http.ResponseWriter, section string, err error) {
	log.Printf("overview page: %s section failed: %v\n", section, err)
	http.Error(w, "template error", http.StatusInternalServerError)
}
