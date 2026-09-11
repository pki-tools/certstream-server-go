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

// shareRow is one slice of the current ingestion rate, by log or by operator.
type shareRow struct {
	Name    string  `json:"name"`
	Rate    float64 `json:"rate"`
	Percent float64 `json:"percent"`
	Logs    int     `json:"logs"`
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

	PrecertShare  float64 `json:"precertShare"`  // percent of processed entries that are precerts
	PublishRate   float64 `json:"publishRate"`   // entries/sec CT as a whole is publishing
	TotalTreeSize int64   `json:"totalTreeSize"` // combined size of every monitored log
	Coverage      float64 `json:"coverage"`      // percent of all known entries we have consumed
	TopOperator   string  `json:"topOperator"`
	TopOperatorPc float64 `json:"topOperatorPc"`
	LogsTiled     int     `json:"logsTiled"`
	LogsRegular   int     `json:"logsRegular"`
}

type dashboardData struct {
	Range         string        `json:"range"`
	BucketSec     int64         `json:"bucketSec"`
	GeneratedAt   string        `json:"generatedAt"`
	TS            []int64       `json:"ts"`
	Rate          []float64     `json:"rate"`
	CertRate      []float64     `json:"certRate"`
	PrecertRate   []float64     `json:"precertRate"`
	Cumulative    []int64       `json:"cumulative"`
	PublishRate   []float64     `json:"publishRate"`
	Backlog       []int64       `json:"backlog"`
	ClientsFull   []int64       `json:"clientsFull"`
	ClientsLite   []int64       `json:"clientsLite"`
	ClientsDomain []int64       `json:"clientsDomain"`
	LogsLive      []int64       `json:"logsLive"`
	LogsBehind    []int64       `json:"logsBehind"`
	Laggards      []namedSeries `json:"laggards"`
	TopLagging    []logRow      `json:"topLagging"`
	TopRate       []logRow      `json:"topRate"`
	ShareByLog    []shareRow    `json:"shareByLog"`
	ShareByOp     []shareRow    `json:"shareByOperator"`
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
		data.CertRate = append(data.CertRate, round2(p.CertRate))
		data.PrecertRate = append(data.PrecertRate, round2(p.PrecertRate))
		data.Cumulative = append(data.Cumulative, p.Total)
		data.Backlog = append(data.Backlog, p.TotalBehind)
		data.ClientsFull = append(data.ClientsFull, int64(p.ClientsFull))
		data.ClientsLite = append(data.ClientsLite, int64(p.ClientsLite))
		data.ClientsDomain = append(data.ClientsDomain, int64(p.ClientsDomain))
		data.LogsLive = append(data.LogsLive, int64(p.LogsLive))
		data.LogsBehind = append(data.LogsBehind, int64(p.LogsBehind))
	}

	data.PublishRate = buildPublishRate(since, bucketSec, data.TS)

	statuses := certificatetransparency.GetLogStatuses()
	data.TopLagging, data.TopRate = buildLeaderboards(statuses)
	data.ShareByLog, data.ShareByOp = buildShares(statuses)
	data.Stats = buildStats(points, statuses, data.PublishRate)
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

// buildPublishRate returns how fast CT as a whole is publishing, aligned to the
// global bucket grid so it can be plotted against our own ingestion rate.
func buildPublishRate(since time.Time, bucketSec int64, grid []int64) []float64 {
	if len(grid) == 0 {
		return nil
	}

	totals, err := dashboardStore.TreeTotals(since, bucketSec)
	if err != nil {
		log.Printf("dashboard: tree totals query failed: %v\n", err)
		return nil
	}

	byTS := make(map[int64]float64, len(totals))
	for _, t := range totals {
		byTS[t.TS] = t.PublishPS
	}

	out := make([]float64, len(grid))
	for i, ts := range grid {
		out[i] = round2(byTS[ts])
	}

	return out
}

// buildShares splits the current ingestion rate by log and by operator. Anything
// past the top slots is folded into "Other" rather than being dropped, so the
// percentages always account for the whole stream.
func buildShares(statuses []certificatetransparency.LogStatusSnapshot) (byLog, byOperator []shareRow) {
	const topSlots = 8

	var total float64
	perOperator := make(map[string]*shareRow)
	logRows := make([]shareRow, 0, len(statuses))

	for _, s := range statuses {
		if s.RatePerSec <= 0 {
			continue
		}

		total += s.RatePerSec
		logRows = append(logRows, shareRow{Name: s.Name, Rate: s.RatePerSec, Logs: 1})

		op, ok := perOperator[s.Operator]
		if !ok {
			op = &shareRow{Name: s.Operator}
			perOperator[s.Operator] = op
		}
		op.Rate += s.RatePerSec
		op.Logs++
	}

	if total <= 0 {
		return nil, nil
	}

	opRows := make([]shareRow, 0, len(perOperator))
	for _, op := range perOperator {
		opRows = append(opRows, *op)
	}

	return topShares(logRows, total, topSlots), topShares(opRows, total, topSlots)
}

// topShares sorts by rate, keeps the top n, and folds the remainder into "Other".
func topShares(rows []shareRow, total float64, n int) []shareRow {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Rate > rows[j].Rate })

	var out []shareRow
	var otherRate float64
	var otherLogs int

	for i, r := range rows {
		if i < n {
			r.Percent = round2(r.Rate / total * 100)
			r.Rate = round2(r.Rate)
			out = append(out, r)

			continue
		}

		otherRate += r.Rate
		otherLogs += r.Logs
	}

	if otherRate > 0 {
		out = append(out, shareRow{
			Name:    "Other",
			Rate:    round2(otherRate),
			Percent: round2(otherRate / total * 100),
			Logs:    otherLogs,
		})
	}

	return out
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
func buildStats(points []dashboard.GlobalPoint, statuses []certificatetransparency.LogStatusSnapshot, publishRate []float64) dashStats {
	certs := certificatetransparency.GetProcessedCerts()
	precerts := certificatetransparency.GetProcessedPrecerts()

	st := dashStats{
		ProcessedTotal: certs + precerts,
		LogsTotal:      len(statuses),
	}

	if total := certs + precerts; total > 0 {
		st.PrecertShare = round2(float64(precerts) / float64(total) * 100)
	}

	var consumed uint64
	operatorRate := make(map[string]float64)
	var totalRate float64

	for _, s := range statuses {
		st.TotalBehind += s.Behind
		st.TotalTreeSize += int64(s.TreeSize)
		consumed += s.CurrentIndex

		if s.Type == "Tiled" {
			st.LogsTiled++
		} else {
			st.LogsRegular++
		}

		if s.TreeSize > 0 {
			if s.Behind == 0 {
				st.LogsLive++
			} else {
				st.LogsBehind++
			}
		}

		if s.RatePerSec > 0 {
			operatorRate[s.Operator] += s.RatePerSec
			totalRate += s.RatePerSec
		}
	}

	if st.TotalTreeSize > 0 {
		st.Coverage = round2(float64(consumed) / float64(st.TotalTreeSize) * 100)
	}

	if totalRate > 0 {
		for op, r := range operatorRate {
			if r > st.TopOperatorPc {
				st.TopOperator, st.TopOperatorPc = op, r
			}
		}
		st.TopOperatorPc = round2(st.TopOperatorPc / totalRate * 100)
	}

	// The newest bucket carries the current CT-wide publish rate.
	for i := len(publishRate) - 1; i >= 0; i-- {
		if publishRate[i] > 0 {
			st.PublishRate = publishRate[i]
			break
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
