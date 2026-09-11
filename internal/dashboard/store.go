// Package dashboard persists periodic snapshots of CT log state to SQLite so the
// web UI can render historical charts without an external Prometheus/Grafana stack.
package dashboard

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver; keeps CGO_ENABLED=0 builds working
)

const schema = `
CREATE TABLE IF NOT EXISTS global_samples (
	ts             INTEGER PRIMARY KEY,
	certs          INTEGER NOT NULL,
	precerts       INTEGER NOT NULL,
	clients_full   INTEGER NOT NULL,
	clients_lite   INTEGER NOT NULL,
	clients_domain INTEGER NOT NULL,
	logs_total     INTEGER NOT NULL,
	logs_live      INTEGER NOT NULL,
	logs_behind    INTEGER NOT NULL,
	total_behind   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS log_samples (
	ts            INTEGER NOT NULL,
	log_url       TEXT NOT NULL,
	current_index INTEGER NOT NULL,
	tree_size     INTEGER NOT NULL,
	behind        INTEGER NOT NULL,
	rate          REAL NOT NULL,
	PRIMARY KEY (ts, log_url)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_log_samples_ts ON log_samples(ts);
`

// Store is a SQLite-backed time series of CT log samples.
type Store struct {
	db *sql.DB
}

// LogSample is one log's state at a point in time.
type LogSample struct {
	URL          string
	CurrentIndex uint64
	TreeSize     uint64
	Behind       uint64
	Rate         float64
}

// Sample is a complete point-in-time observation of the server and all its logs.
type Sample struct {
	Certs         int64
	Precerts      int64
	ClientsFull   int64
	ClientsLite   int64
	ClientsDomain int64
	LogsTotal     int
	LogsLive      int
	LogsBehind    int
	TotalBehind   uint64
	Logs          []LogSample
}

// Open opens (creating if needed) the SQLite database at path and applies the schema.
func Open(path string) (*Store, error) {
	// WAL lets the sampler write while the page reads; busy_timeout avoids
	// spurious "database is locked" errors under that overlap.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening dashboard db: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to dashboard db: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying dashboard schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Insert writes one sample (global row plus one row per log) in a single transaction.
func (s *Store) Insert(ts time.Time, sample Sample) error {
	unix := ts.Unix()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT OR REPLACE INTO global_samples
		 (ts, certs, precerts, clients_full, clients_lite, clients_domain,
		  logs_total, logs_live, logs_behind, total_behind)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		unix, sample.Certs, sample.Precerts,
		sample.ClientsFull, sample.ClientsLite, sample.ClientsDomain,
		sample.LogsTotal, sample.LogsLive, sample.LogsBehind, sample.TotalBehind,
	)
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(
		`INSERT OR REPLACE INTO log_samples
		 (ts, log_url, current_index, tree_size, behind, rate) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, l := range sample.Logs {
		if _, err := stmt.Exec(unix, l.URL, l.CurrentIndex, l.TreeSize, l.Behind, l.Rate); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Prune deletes samples older than the retention window.
func (s *Store) Prune(retention time.Duration) error {
	cutoff := time.Now().Add(-retention).Unix()

	if _, err := s.db.Exec(`DELETE FROM global_samples WHERE ts < ?`, cutoff); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM log_samples WHERE ts < ?`, cutoff); err != nil {
		return err
	}

	return nil
}

// GlobalPoint is one bucketed point of the global time series.
// Rate is derived from the cumulative certificate counters, not stored directly.
type GlobalPoint struct {
	TS            int64   `json:"ts"`
	Rate          float64 `json:"rate"`
	CertRate      float64 `json:"certRate"`
	PrecertRate   float64 `json:"precertRate"`
	ClientsFull   int     `json:"clientsFull"`
	ClientsLite   int     `json:"clientsLite"`
	ClientsDomain int     `json:"clientsDomain"`
	LogsLive      int     `json:"logsLive"`
	LogsBehind    int     `json:"logsBehind"`
	TotalBehind   int64   `json:"backlog"`

	// Total is the cumulative certs+precerts counter at this bucket. It backs the
	// derived Rate and window totals, and is charted as the growth curve.
	Total int64 `json:"-"`

	// certs and precerts are the separate cumulative counters behind CertRate
	// and PrecertRate.
	certs    int64
	precerts int64

	// lastTS is the newest sample timestamp inside the bucket. Rate is timed
	// against this rather than the bucket floor, so a partial trailing bucket
	// (and any gap in sampling) still yields a true rate.
	lastTS int64
}

// GlobalSeries returns the global time series since `since`, bucketed to bucketSec
// so a 7-day window returns roughly the same number of points as a 1-hour window.
func (s *Store) GlobalSeries(since time.Time, bucketSec int64) ([]GlobalPoint, error) {
	if bucketSec < 1 {
		bucketSec = 1
	}

	rows, err := s.db.Query(
		`SELECT (ts/?)*? AS bucket, MAX(ts),
		        MAX(certs), MAX(precerts),
		        AVG(clients_full), AVG(clients_lite), AVG(clients_domain),
		        AVG(logs_live), AVG(logs_behind), AVG(total_behind)
		 FROM global_samples
		 WHERE ts >= ?
		 GROUP BY bucket
		 ORDER BY bucket`,
		bucketSec, bucketSec, since.Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []GlobalPoint

	for rows.Next() {
		var p GlobalPoint
		var certs, precerts int64
		var cf, cl, cd, live, behind, backlog float64

		if err := rows.Scan(&p.TS, &p.lastTS, &certs, &precerts, &cf, &cl, &cd, &live, &behind, &backlog); err != nil {
			return nil, err
		}

		p.Total = certs + precerts
		p.certs = certs
		p.precerts = precerts
		p.ClientsFull = int(cf + 0.5)
		p.ClientsLite = int(cl + 0.5)
		p.ClientsDomain = int(cd + 0.5)
		p.LogsLive = int(live + 0.5)
		p.LogsBehind = int(behind + 0.5)
		p.TotalBehind = int64(backlog + 0.5)

		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	deriveRates(points)

	return points, nil
}

// deriveRates fills in Rate from the delta of the cumulative counter between
// consecutive buckets. A negative delta means the process restarted and the
// counter reset, so that bucket carries no meaningful rate.
func deriveRates(points []GlobalPoint) {
	for i := 1; i < len(points); i++ {
		dt := points[i].lastTS - points[i-1].lastTS
		if dt <= 0 {
			continue
		}

		if d := points[i].Total - points[i-1].Total; d >= 0 {
			points[i].Rate = float64(d) / float64(dt)
		}
		if d := points[i].certs - points[i-1].certs; d >= 0 {
			points[i].CertRate = float64(d) / float64(dt)
		}
		if d := points[i].precerts - points[i-1].precerts; d >= 0 {
			points[i].PrecertRate = float64(d) / float64(dt)
		}
	}

	// The first bucket has no predecessor to diff against; carry the second
	// bucket's rates back so the charts don't open with a false zero.
	if len(points) > 1 {
		points[0].Rate = points[1].Rate
		points[0].CertRate = points[1].CertRate
		points[0].PrecertRate = points[1].PrecertRate
	}
}

// LogSeries returns per-log backlog history for the given log URLs, bucketed to
// bucketSec. The result maps each URL to its points in ascending time order.
func (s *Store) LogSeries(since time.Time, bucketSec int64, urls []string) (map[string][]BacklogPoint, error) {
	if len(urls) == 0 {
		return map[string][]BacklogPoint{}, nil
	}
	if bucketSec < 1 {
		bucketSec = 1
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(urls)), ",")
	args := []any{bucketSec, bucketSec, since.Unix()}
	for _, u := range urls {
		args = append(args, u)
	}

	query := fmt.Sprintf(
		`SELECT (ts/?)*? AS bucket, log_url, AVG(behind)
		 FROM log_samples
		 WHERE ts >= ? AND log_url IN (%s)
		 GROUP BY bucket, log_url
		 ORDER BY bucket`, placeholders)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string][]BacklogPoint, len(urls))

	for rows.Next() {
		var ts int64
		var url string
		var behind float64

		if err := rows.Scan(&ts, &url, &behind); err != nil {
			return nil, err
		}

		out[url] = append(out[url], BacklogPoint{TS: ts, Behind: int64(behind + 0.5)})
	}

	return out, rows.Err()
}

// TreeTotalPoint is the combined tree size of every monitored log at one bucket.
// Measured counts how many logs contributed a non-zero tree size, which is what
// makes the derived publish rate trustworthy: the total jumps whenever a log is
// polled for the first time, so a bucket whose measured count changed cannot be
// compared against its predecessor.
type TreeTotalPoint struct {
	TS        int64
	LastTS    int64
	TreeSize  int64
	Measured  int
	PublishPS float64
}

// TreeTotals returns the aggregate tree size across all logs, bucketed. Each log
// contributes one averaged value per bucket so that logs sampled more than once
// in a bucket are not counted repeatedly.
func (s *Store) TreeTotals(since time.Time, bucketSec int64) ([]TreeTotalPoint, error) {
	if bucketSec < 1 {
		bucketSec = 1
	}

	// MAX rather than AVG: tree size is a monotonic counter, so the newest reading
	// in the bucket is the right one. Averaging would fold in the zeros a log
	// carries before its first successful tree-size poll, understating early
	// buckets and manufacturing a huge apparent jump in the next one.
	rows, err := s.db.Query(
		`SELECT bucket, MAX(last_ts), SUM(max_tree), SUM(measured) FROM (
		     SELECT (ts/?)*? AS bucket, MAX(ts) AS last_ts, log_url,
		            MAX(tree_size) AS max_tree,
		            CASE WHEN MAX(tree_size) > 0 THEN 1 ELSE 0 END AS measured
		     FROM log_samples
		     WHERE ts >= ?
		     GROUP BY bucket, log_url
		 )
		 GROUP BY bucket
		 ORDER BY bucket`,
		bucketSec, bucketSec, since.Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []TreeTotalPoint

	for rows.Next() {
		var p TreeTotalPoint
		var treeSize float64

		if err := rows.Scan(&p.TS, &p.LastTS, &treeSize, &p.Measured); err != nil {
			return nil, err
		}

		p.TreeSize = int64(treeSize)
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	derivePublishRate(points)

	return points, nil
}

// derivePublishRate fills in how fast CT as a whole is publishing entries. It is
// only meaningful between buckets covering the same set of measured logs; when
// that set changes the total moves for bookkeeping reasons rather than growth.
func derivePublishRate(points []TreeTotalPoint) {
	for i := 1; i < len(points); i++ {
		if points[i].Measured != points[i-1].Measured {
			continue
		}

		dt := points[i].LastTS - points[i-1].LastTS
		d := points[i].TreeSize - points[i-1].TreeSize

		if dt > 0 && d >= 0 {
			points[i].PublishPS = float64(d) / float64(dt)
		}
	}
}

// BacklogPoint is one bucketed backlog reading for a single log.
type BacklogPoint struct {
	TS     int64 `json:"ts"`
	Behind int64 `json:"behind"`
}

// SampleCount returns how many global samples are currently stored, and the
// timestamp of the oldest one. Used to tell the user how much history exists.
func (s *Store) SampleCount() (count int64, oldest time.Time) {
	var ts sql.NullInt64
	if err := s.db.QueryRow(`SELECT COUNT(*), MIN(ts) FROM global_samples`).Scan(&count, &ts); err != nil {
		log.Printf("dashboard: could not read sample count: %v\n", err)
		return 0, time.Time{}
	}

	if ts.Valid {
		oldest = time.Unix(ts.Int64, 0)
	}

	return count, oldest
}
