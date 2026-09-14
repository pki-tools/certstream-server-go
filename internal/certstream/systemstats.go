package certstream

import (
	"context"
	"runtime"
	"runtime/metrics"
	"sync"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

const (
	// statsInterval is how often runtime and pipeline counters are sampled.
	statsInterval = 2 * time.Second
	// statsWindow is how many samples are kept, giving about three minutes of
	// history for the sparklines and the rolling verdict.
	statsWindow = 90
)

// statSample is one point-in-time reading. Counters are cumulative; the rates
// shown on the page come from differencing consecutive samples.
type statSample struct {
	At         time.Time
	Processed  int64
	CPUSeconds float64
	GCSeconds  float64
	Goroutines int
	HeapBytes  uint64
	GCCycles   uint32

	Timing certificatetransparency.PipelineTiming

	CertChanDepth  int64
	CertChanCap    int64
	BroadcastDepth int
	BroadcastCap   int
}

var statsRing = struct {
	mu      sync.RWMutex
	samples []statSample
}{}

// cpuMetricNames are runtime/metrics keys for process CPU accounting. They are
// portable across platforms but may be reported as unsupported, in which case
// the CPU figures are simply omitted rather than guessed at.
var cpuMetricNames = []string{
	"/cpu/classes/total:cpu-seconds",
	"/cpu/classes/gc/total:cpu-seconds",
}

// StartSystemStats begins sampling runtime and pipeline counters.
func StartSystemStats(ctx context.Context) {
	go func() {
		collectStatSample()

		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				collectStatSample()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func collectStatSample() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	samples := make([]metrics.Sample, len(cpuMetricNames))
	for i, name := range cpuMetricNames {
		samples[i].Name = name
	}
	metrics.Read(samples)

	var cpuSeconds, gcSeconds float64
	if samples[0].Value.Kind() == metrics.KindFloat64 {
		cpuSeconds = samples[0].Value.Float64()
	}
	if samples[1].Value.Kind() == metrics.KindFloat64 {
		gcSeconds = samples[1].Value.Float64()
	}

	certDepth, certCap := certificatetransparency.GetPipelineDepth()
	bcDepth, bcCap := web.ClientHandler.QueueDepth()

	s := statSample{
		At:             time.Now(),
		Processed:      certificatetransparency.GetProcessedCerts() + certificatetransparency.GetProcessedPrecerts(),
		CPUSeconds:     cpuSeconds,
		GCSeconds:      gcSeconds,
		Goroutines:     runtime.NumGoroutine(),
		HeapBytes:      mem.HeapAlloc,
		GCCycles:       mem.NumGC,
		Timing:         certificatetransparency.GetPipelineTiming(),
		CertChanDepth:  certDepth,
		CertChanCap:    certCap,
		BroadcastDepth: bcDepth,
		BroadcastCap:   bcCap,
	}

	statsRing.mu.Lock()
	statsRing.samples = append(statsRing.samples, s)
	if len(statsRing.samples) > statsWindow {
		statsRing.samples = statsRing.samples[len(statsRing.samples)-statsWindow:]
	}
	statsRing.mu.Unlock()
}

func snapshotSamples() []statSample {
	statsRing.mu.RLock()
	defer statsRing.mu.RUnlock()

	out := make([]statSample, len(statsRing.samples))
	copy(out, statsRing.samples)

	return out
}

// Bottleneck names the pipeline stage currently limiting throughput.
type Bottleneck struct {
	Stage   string
	Detail  string
	WaitIn  float64 // percent of certHandler time spent waiting for input
	WaitOut float64 // percent blocked sending downstream
	Busy    float64 // percent doing its own work
	Known   bool
}

// classifyBottleneck reads the split of certHandler's time over the sampled
// window. Cumulative totals would be dominated by startup, so only the delta
// between the oldest and newest sample is considered.
func classifyBottleneck(samples []statSample) Bottleneck {
	if len(samples) < 2 {
		return Bottleneck{Stage: "Measuring", Detail: "Collecting samples — check back in a few seconds."}
	}

	first, last := samples[0], samples[len(samples)-1]

	in := float64(last.Timing.WaitIn - first.Timing.WaitIn)
	out := float64(last.Timing.WaitOut - first.Timing.WaitOut)
	busy := float64(last.Timing.Busy - first.Timing.Busy)
	total := in + out + busy

	if total <= 0 || last.Timing.Handled == first.Timing.Handled {
		return Bottleneck{Stage: "Idle", Detail: "No certificates moved through the pipeline during this window."}
	}

	b := Bottleneck{
		WaitIn:  in / total * 100,
		WaitOut: out / total * 100,
		Busy:    busy / total * 100,
		Known:   true,
	}

	switch {
	case b.WaitOut >= 20:
		b.Stage = "Broadcasting"
		b.Detail = "The handler spends much of its time blocked handing certificates downstream, so JSON encoding and fan-out to clients is the limit. Processing, not downloading, is the constraint. Check skipped certificates and client count below; raising buffer_sizes.broadcastmanager only defers the problem."
	case b.Busy >= 25:
		b.Stage = "Entry handling"
		b.Detail = "The handler is CPU-bound in its own work rather than waiting at either end. This is the single goroutine that fans every certificate out, so it is a hard ceiling on total throughput."
	default:
		b.Stage = "Fetching"
		b.Detail = "The handler is mostly idle waiting for certificates to arrive, so downloading is the limit rather than processing. Look at scanner.batch_size and parallel_fetch, and check /errors for throttling."
	}

	return b
}

// rateOver returns certificates per second across the sampled window.
func rateOver(samples []statSample) float64 {
	if len(samples) < 2 {
		return 0
	}

	first, last := samples[0], samples[len(samples)-1]

	elapsed := last.At.Sub(first.At).Seconds()
	if elapsed <= 0 {
		return 0
	}

	if d := last.Processed - first.Processed; d > 0 {
		return float64(d) / elapsed
	}

	return 0
}

// cpuPercentOver returns process CPU utilisation across the window, as a
// percentage of one core. It can exceed 100 on a multi-core machine.
func cpuPercentOver(samples []statSample) (total, gc float64, known bool) {
	if len(samples) < 2 {
		return 0, 0, false
	}

	first, last := samples[0], samples[len(samples)-1]
	if first.CPUSeconds == 0 && last.CPUSeconds == 0 {
		return 0, 0, false
	}

	elapsed := last.At.Sub(first.At).Seconds()
	if elapsed <= 0 {
		return 0, 0, false
	}

	return (last.CPUSeconds - first.CPUSeconds) / elapsed * 100,
		(last.GCSeconds - first.GCSeconds) / elapsed * 100,
		true
}
