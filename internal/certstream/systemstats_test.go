package certstream

import (
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
)

// samplePair builds two samples whose timing delta has the given shape, which is
// what classifyBottleneck actually reads.
func samplePair(in, out, busy time.Duration, handled int64) []statSample {
	start := time.Now().Add(-time.Minute)

	return []statSample{
		{At: start},
		{
			At: start.Add(time.Minute),
			Timing: certificatetransparency.PipelineTiming{
				WaitIn: in, WaitOut: out, Busy: busy, Handled: handled,
			},
		},
	}
}

func TestClassifyBottleneck(t *testing.T) {
	tests := []struct {
		name      string
		in        time.Duration
		out       time.Duration
		busy      time.Duration
		handled   int64
		wantStage string
	}{
		{
			name: "starved handler is fetch bound",
			in:   95 * time.Second, out: 2 * time.Second, busy: 3 * time.Second,
			handled: 1000, wantStage: "Fetching",
		},
		{
			name: "blocked downstream is broadcast bound",
			in:   30 * time.Second, out: 60 * time.Second, busy: 10 * time.Second,
			handled: 1000, wantStage: "Broadcasting",
		},
		{
			name: "cpu bound in the handler itself",
			in:   50 * time.Second, out: 5 * time.Second, busy: 45 * time.Second,
			handled: 1000, wantStage: "Entry handling",
		},
		{
			name: "output wait wins even when input wait is larger",
			in:   60 * time.Second, out: 25 * time.Second, busy: 15 * time.Second,
			handled: 1000, wantStage: "Broadcasting",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBottleneck(samplePair(tc.in, tc.out, tc.busy, tc.handled))

			if got.Stage != tc.wantStage {
				t.Errorf("stage = %q, want %q (in=%.0f%% out=%.0f%% busy=%.0f%%)",
					got.Stage, tc.wantStage, got.WaitIn, got.WaitOut, got.Busy)
			}
			if !got.Known {
				t.Error("expected a known verdict")
			}

			if sum := got.WaitIn + got.WaitOut + got.Busy; sum < 99.5 || sum > 100.5 {
				t.Errorf("percentages sum to %.2f, want 100", sum)
			}
		})
	}
}

func TestClassifyBottleneckNeedsSamples(t *testing.T) {
	if got := classifyBottleneck(nil).Stage; got != "Measuring" {
		t.Errorf("stage = %q, want Measuring", got)
	}

	if got := classifyBottleneck([]statSample{{At: time.Now()}}).Stage; got != "Measuring" {
		t.Errorf("single sample stage = %q, want Measuring", got)
	}
}

// An idle pipeline must not be reported as a bottleneck.
func TestClassifyBottleneckIdle(t *testing.T) {
	got := classifyBottleneck(samplePair(0, 0, 0, 0))

	if got.Stage != "Idle" {
		t.Errorf("stage = %q, want Idle", got.Stage)
	}
	if got.Known {
		t.Error("an idle pipeline should not claim a known bottleneck")
	}
}

func TestRateOver(t *testing.T) {
	start := time.Now().Add(-10 * time.Second)
	samples := []statSample{
		{At: start, Processed: 1000},
		{At: start.Add(10 * time.Second), Processed: 3000},
	}

	if got := rateOver(samples); got < 199 || got > 201 {
		t.Errorf("rate = %.2f, want ~200/sec", got)
	}

	// A counter reset (restart) must not produce a negative rate.
	reset := []statSample{
		{At: start, Processed: 5000},
		{At: start.Add(10 * time.Second), Processed: 10},
	}
	if got := rateOver(reset); got != 0 {
		t.Errorf("rate after counter reset = %.2f, want 0", got)
	}
}
