package certificatetransparency

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
)

// LogState is an operator's control over ingestion from one log.
type LogState string

const (
	// LogRunning is the default: the log is ingested normally.
	LogRunning LogState = "running"
	// LogPaused halts ingestion until resumed. Not persisted: a restart
	// resumes every paused log.
	LogPaused LogState = "paused"
	// LogStopped halts ingestion and stays halted across restarts until
	// resumed - for a log that should not be ingested at all for now.
	LogStopped LogState = "stopped"
)

// ParseLogState validates a state name.
func ParseLogState(s string) (LogState, bool) {
	switch LogState(s) {
	case LogRunning, LogPaused, LogStopped:
		return LogState(s), true
	default:
		return "", false
	}
}

// Pausing or stopping a log holds its worker at a safe point rather than
// tearing it down:
//
//   - The worker waits in waitWhileHeld before each fetch cycle, so a held log
//     makes no requests at all.
//   - A fetch already under way runs on heldContext, which is cancelled the
//     moment the log leaves LogRunning. Entries already fetched are still
//     handed on - both fetch loops finish what they have dispatched on the
//     worker's own lifetime, not on the held context - so pausing loses
//     nothing, and resuming continues from where ingestion stopped.
//
// Changes are broadcast by closing the log's changed channel and replacing it,
// so any number of waiters wake at once without polling.

type logControl struct {
	state   LogState
	changed chan struct{}
}

var logControls = struct {
	mu   sync.Mutex
	logs map[string]*logControl
	// file persists stopped logs; empty disables persistence.
	file string
}{logs: make(map[string]*logControl)}

// controlFor returns a log's control entry, creating it in LogRunning.
// Callers must hold logControls.mu.
func controlFor(normURL string) *logControl {
	c, ok := logControls.logs[normURL]
	if !ok {
		c = &logControl{state: LogRunning, changed: make(chan struct{})}
		logControls.logs[normURL] = c
	}

	return c
}

// GetLogState returns a log's current state.
func GetLogState(normURL string) LogState {
	logControls.mu.Lock()
	defer logControls.mu.Unlock()

	if c, ok := logControls.logs[normURL]; ok {
		return c.state
	}

	return LogRunning
}

// SetLogState changes a log's state, waking anything waiting on it, and
// persists the set of stopped logs when that set changes.
func SetLogState(normURL string, state LogState) error {
	logControls.mu.Lock()

	c := controlFor(normURL)
	if c.state == state {
		logControls.mu.Unlock()
		return nil
	}

	persist := c.state == LogStopped || state == LogStopped
	prev := c.state
	c.state = state

	close(c.changed)
	c.changed = make(chan struct{})

	var snapshot []string
	if persist {
		snapshot = stoppedLogsLocked()
	}

	file := logControls.file
	logControls.mu.Unlock()

	log.Printf("Log control: '%s' %s -> %s\n", normURL, prev, state)

	if persist && file != "" {
		if err := writeStoppedLogs(file, snapshot); err != nil {
			return fmt.Errorf("state changed but could not be saved: %w", err)
		}
	}

	return nil
}

// waitWhileHeld blocks while the log is paused or stopped. It returns false
// if ctx ends first.
func waitWhileHeld(ctx context.Context, normURL string) bool {
	for {
		logControls.mu.Lock()
		c := controlFor(normURL)
		state, changed := c.state, c.changed
		logControls.mu.Unlock()

		if state == LogRunning {
			return true
		}

		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

// heldContext returns a child of ctx that is cancelled as soon as the log
// leaves LogRunning, for bounding a fetch cycle.
func heldContext(ctx context.Context, normURL string) (context.Context, context.CancelFunc) {
	hctx, cancel := context.WithCancel(ctx)

	go func() {
		defer cancel()

		for {
			logControls.mu.Lock()
			c := controlFor(normURL)
			state, changed := c.state, c.changed
			logControls.mu.Unlock()

			if state != LogRunning {
				return
			}

			select {
			case <-changed:
			case <-hctx.Done():
				return
			}
		}
	}()

	return hctx, cancel
}

func stoppedLogsLocked() []string {
	var out []string

	for url, c := range logControls.logs {
		if c.state == LogStopped {
			out = append(out, url)
		}
	}

	sort.Strings(out)

	return out
}

type stoppedLogsFile struct {
	Stopped []string `json:"stopped"`
}

// writeStoppedLogs saves atomically: a crash mid-write leaves the old file.
func writeStoppedLogs(path string, stopped []string) error {
	data, err := json.MarshalIndent(stoppedLogsFile{Stopped: stopped}, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}

// LoadLogControls sets the persistence file and restores stopped logs from it.
// It must run before workers start, so a stopped log never begins ingesting.
// A missing file is not an error.
func LoadLogControls(path string) error {
	logControls.mu.Lock()
	defer logControls.mu.Unlock()

	logControls.file = path
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return err
	}

	var f stoppedLogsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	for _, url := range f.Stopped {
		controlFor(url).state = LogStopped
	}

	if len(f.Stopped) > 0 {
		log.Printf("Log control: %d log(s) stopped by operator, not ingesting: %v\n", len(f.Stopped), f.Stopped)
	}

	return nil
}

// RegisterLogForTest registers a regular log for status and control, as a
// worker would. Test-only.
func RegisterLogForTest(rawURL, name, operator string) {
	registerLogForStatus(rawURL, name, operator, LogTypeRegular, nil)
}

// ResetLogControlsForTest returns every log to LogRunning and disables
// persistence. Test-only.
func ResetLogControlsForTest() {
	logControls.mu.Lock()
	defer logControls.mu.Unlock()

	for _, c := range logControls.logs {
		close(c.changed)
	}

	logControls.logs = make(map[string]*logControl)
	logControls.file = ""
}
