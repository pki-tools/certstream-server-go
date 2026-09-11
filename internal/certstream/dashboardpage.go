package certstream

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/dashboard"
)

// dashboardStore is set by registerDashboard when the dashboard is enabled in config.
var dashboardStore *dashboard.Store

// targetPoints is the number of buckets each time range is downsampled to, so a
// 7-day window renders about as many marks as a 1-hour one.
const targetPoints = 120

// topLogCount is how many logs appear in the leaderboards and the per-log chart.
const topLogCount = 5

var dashboardRanges = map[string]time.Duration{
	"1h":  time.Hour,
	"12h": 12 * time.Hour,
	"24h": 24 * time.Hour,
	"3d":  72 * time.Hour,
	"7d":  168 * time.Hour,
}

type logRow struct {
	Name     string  `json:"name"`
	Operator string  `json:"operator"`
	Type     string  `json:"type"`
	Behind   uint64  `json:"behind"`
	Rate     float64 `json:"rate"`
	ETASecs  int64   `json:"etaSecs"` // -1 unknown, 0 live
}

type namedSeries struct {
	Name string  `json:"name"`
	Vals []int64 `json:"vals"`
}

type dashStats struct {
	CurrentRate    float64 `json:"currentRate"`
	PeakRate       float64 `json:"peakRate"`
	AvgRate        float64 `json:"avgRate"`
	CertsInWindow  int64   `json:"certsInWindow"`
	TotalBehind    uint64  `json:"totalBehind"`
	LogsTotal      int     `json:"logsTotal"`
	LogsLive       int     `json:"logsLive"`
	LogsBehind     int     `json:"logsBehind"`
	ClientsNow     int     `json:"clientsNow"`
	ProcessedTotal int64   `json:"processedTotal"`
	SampleCount    int64   `json:"sampleCount"`
	HistorySecs    int64   `json:"historySecs"`
}

type dashboardData struct {
	Range         string        `json:"range"`
	BucketSec     int64         `json:"bucketSec"`
	GeneratedAt   string        `json:"generatedAt"`
	TS            []int64       `json:"ts"`
	Rate          []float64     `json:"rate"`
	Backlog       []int64       `json:"backlog"`
	ClientsFull   []int64       `json:"clientsFull"`
	ClientsLite   []int64       `json:"clientsLite"`
	ClientsDomain []int64       `json:"clientsDomain"`
	LogsLive      []int64       `json:"logsLive"`
	LogsBehind    []int64       `json:"logsBehind"`
	Laggards      []namedSeries `json:"laggards"`
	TopLagging    []logRow      `json:"topLagging"`
	TopRate       []logRow      `json:"topRate"`
	Stats         dashStats     `json:"stats"`
}

// dashboardDataHandler serves the JSON backing the dashboard charts.
func dashboardDataHandler(w http.ResponseWriter, r *http.Request) {
	if dashboardStore == nil {
		http.Error(w, "dashboard disabled", http.StatusNotFound)
		return
	}

	rangeKey := r.URL.Query().Get("range")
	window, ok := dashboardRanges[rangeKey]
	if !ok {
		rangeKey = "24h"
		window = 24 * time.Hour
	}

	bucketSec := int64(window.Seconds()) / targetPoints
	if minBucket := int64(sampleIntervalSeconds()); bucketSec < minBucket {
		bucketSec = minBucket
	}

	since := time.Now().Add(-window)

	points, err := dashboardStore.GlobalSeries(since, bucketSec)
	if err != nil {
		log.Printf("dashboard: global series query failed: %v\n", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	data := dashboardData{
		Range:       rangeKey,
		BucketSec:   bucketSec,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}

	for _, p := range points {
		data.TS = append(data.TS, p.TS)
		data.Rate = append(data.Rate, round2(p.Rate))
		data.Backlog = append(data.Backlog, p.TotalBehind)
		data.ClientsFull = append(data.ClientsFull, int64(p.ClientsFull))
		data.ClientsLite = append(data.ClientsLite, int64(p.ClientsLite))
		data.ClientsDomain = append(data.ClientsDomain, int64(p.ClientsDomain))
		data.LogsLive = append(data.LogsLive, int64(p.LogsLive))
		data.LogsBehind = append(data.LogsBehind, int64(p.LogsBehind))
	}

	statuses := certificatetransparency.GetLogStatuses()
	data.TopLagging, data.TopRate = buildLeaderboards(statuses)
	data.Stats = buildStats(points, statuses)
	data.Laggards = buildLaggardSeries(data.TopLagging, statuses, since, bucketSec, data.TS)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("dashboard: encoding response failed: %v\n", err)
	}
}

// buildLeaderboards returns the most-lagging and fastest logs by current state.
func buildLeaderboards(statuses []certificatetransparency.LogStatusSnapshot) (lagging, fastest []logRow) {
	rows := make([]logRow, 0, len(statuses))
	for _, s := range statuses {
		eta := int64(-1)
		if s.ETA == 0 {
			eta = 0
		} else if s.ETA > 0 {
			eta = int64(s.ETA.Seconds())
		}

		rows = append(rows, logRow{
			Name:     s.Name,
			Operator: s.Operator,
			Type:     s.Type,
			Behind:   s.Behind,
			Rate:     round2(s.RatePerSec),
			ETASecs:  eta,
		})
	}

	byBehind := make([]logRow, len(rows))
	copy(byBehind, rows)
	sort.Slice(byBehind, func(i, j int) bool { return byBehind[i].Behind > byBehind[j].Behind })

	byRate := make([]logRow, len(rows))
	copy(byRate, rows)
	sort.Slice(byRate, func(i, j int) bool { return byRate[i].Rate > byRate[j].Rate })

	return trimRows(byBehind, func(r logRow) bool { return r.Behind > 0 }),
		trimRows(byRate, func(r logRow) bool { return r.Rate > 0 })
}

// trimRows keeps at most topLogCount rows that satisfy keep.
func trimRows(rows []logRow, keep func(logRow) bool) []logRow {
	out := make([]logRow, 0, topLogCount)
	for _, r := range rows {
		if !keep(r) {
			break
		}
		out = append(out, r)
		if len(out) == topLogCount {
			break
		}
	}
	return out
}

// buildStats derives the headline figures from the window and current state.
func buildStats(points []dashboard.GlobalPoint, statuses []certificatetransparency.LogStatusSnapshot) dashStats {
	st := dashStats{
		ProcessedTotal: certificatetransparency.GetProcessedCerts() + certificatetransparency.GetProcessedPrecerts(),
		LogsTotal:      len(statuses),
	}

	for _, s := range statuses {
		st.TotalBehind += s.Behind
		if s.TreeSize > 0 {
			if s.Behind == 0 {
				st.LogsLive++
			} else {
				st.LogsBehind++
			}
		}
	}

	if len(points) > 0 {
		last := points[len(points)-1]
		st.CurrentRate = round2(last.Rate)
		st.ClientsNow = last.ClientsFull + last.ClientsLite + last.ClientsDomain

		var sum float64
		for _, p := range points {
			if p.Rate > st.PeakRate {
				st.PeakRate = p.Rate
			}
			sum += p.Rate
		}
		st.PeakRate = round2(st.PeakRate)
		st.AvgRate = round2(sum / float64(len(points)))

		if d := last.Total - points[0].Total; d > 0 {
			st.CertsInWindow = d
		}
	}

	count, oldest := dashboardStore.SampleCount()
	st.SampleCount = count
	if !oldest.IsZero() {
		st.HistorySecs = int64(time.Since(oldest).Seconds())
	}

	return st
}

// buildLaggardSeries returns backlog history for the top lagging logs, aligned to
// the shared bucket grid so the client can plot them against one x axis.
func buildLaggardSeries(top []logRow, statuses []certificatetransparency.LogStatusSnapshot,
	since time.Time, bucketSec int64, grid []int64,
) []namedSeries {
	if len(top) == 0 || len(grid) == 0 {
		return nil
	}

	// The leaderboard carries display names; the store is keyed by URL.
	urlByName := make(map[string]string, len(statuses))
	for _, s := range statuses {
		urlByName[s.Name] = s.URL
	}

	urls := make([]string, 0, len(top))
	nameByURL := make(map[string]string, len(top))
	for _, r := range top {
		if u, ok := urlByName[r.Name]; ok {
			urls = append(urls, u)
			nameByURL[u] = r.Name
		}
	}

	series, err := dashboardStore.LogSeries(since, bucketSec, urls)
	if err != nil {
		log.Printf("dashboard: per-log series query failed: %v\n", err)
		return nil
	}

	out := make([]namedSeries, 0, len(urls))
	for _, u := range urls {
		byTS := make(map[int64]int64, len(series[u]))
		for _, p := range series[u] {
			byTS[p.TS] = p.Behind
		}

		vals := make([]int64, len(grid))
		for i, ts := range grid {
			vals[i] = byTS[ts]
		}

		out = append(out, namedSeries{Name: nameByURL[u], Vals: vals})
	}

	return out
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}

// sampleIntervalSeconds is the floor for bucket width — bucketing finer than the
// sampling cadence just produces empty buckets.
func sampleIntervalSeconds() int {
	if n := config.AppConfig.General.Dashboard.SampleInterval; n > 0 {
		return n
	}
	return 60
}

func dashboardHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write([]byte(dashboardHTML)); err != nil {
		log.Printf("dashboard: writing page failed: %v\n", err)
	}
}
