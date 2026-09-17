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

	// UserSeconds and ScavengeSeconds break the CPU total down further, so a run
	// dominated by GC or by the scavenger is distinguishable from real work.
	UserSeconds     float64
	ScavengeSeconds float64
	// AllocBytes is cumulative heap allocation, which drives GC pressure.
	AllocBytes uint64
	// GCPauseP50/P99 are recent stop-the-world pause quantiles.
	GCPauseP50 time.Duration
	GCPauseP99 time.Duration

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
	"/cpu/classes/user:cpu-seconds",
	"/cpu/classes/scavenge/total:cpu-seconds",
	"/gc/heap/allocs:bytes",
	"/gc/pauses:seconds",
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

	readFloat := func(i int) float64 {
		if samples[i].Value.Kind() == metrics.KindFloat64 {
			return samples[i].Value.Float64()
		}

		return 0
	}

	cpuSeconds := readFloat(0)
	gcSeconds := readFloat(1)
	userSeconds := readFloat(2)
	scavengeSeconds := readFloat(3)

	var allocBytes uint64
	if samples[4].Value.Kind() == metrics.KindUint64 {
		allocBytes = samples[4].Value.Uint64()
	}

	var p50, p99 time.Duration
	if samples[5].Value.Kind() == metrics.KindFloat64Histogram {
		p50 = histogramQuantile(samples[5].Value.Float64Histogram(), 0.50)
		p99 = histogramQuantile(samples[5].Value.Float64Histogram(), 0.99)
	}

	certDepth, certCap := certificatetransparency.GetPipelineDepth()
	bcDepth, bcCap := web.ClientHandler.QueueDepth()

	s := statSample{
		At:              time.Now(),
		Processed:       certificatetransparency.GetProcessedCerts() + certificatetransparency.GetProcessedPrecerts(),
		CPUSeconds:      cpuSeconds,
		GCSeconds:       gcSeconds,
		UserSeconds:     userSeconds,
		ScavengeSeconds: scavengeSeconds,
		AllocBytes:      allocBytes,
		GCPauseP50:      p50,
		GCPauseP99:      p99,
		Goroutines:      runtime.NumGoroutine(),
		HeapBytes:       mem.HeapAlloc,
		GCCycles:        mem.NumGC,
		Timing:          certificatetransparency.GetPipelineTiming(),
		CertChanDepth:   certDepth,
		CertChanCap:     certCap,
		BroadcastDepth:  bcDepth,
		BroadcastCap:    bcCap,
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

// histogramQuantile approximates a quantile from a runtime/metrics histogram.
// Counts are cumulative for the process lifetime, so these describe pause
// behaviour since startup rather than only the recent window.
func histogramQuantile(h *metrics.Float64Histogram, q float64) time.Duration {
	if h == nil || len(h.Counts) == 0 {
		return 0
	}

	var total uint64
	for _, c := range h.Counts {
		total += c
	}

	if total == 0 {
		return 0
	}

	target := uint64(float64(total) * q)

	var running uint64
	for i, c := range h.Counts {
		running += c
		if running >= target {
			// Bucket i covers [Buckets[i], Buckets[i+1]); report its upper edge.
			if i+1 < len(h.Buckets) {
				return time.Duration(h.Buckets[i+1] * float64(time.Second))
			}

			return time.Duration(h.Buckets[i] * float64(time.Second))
		}
	}

	return 0
}

// allocRateOver returns bytes allocated per second across the window.
func allocRateOver(samples []statSample) float64 {
	if len(samples) < 2 {
		return 0
	}

	first, last := samples[0], samples[len(samples)-1]

	elapsed := last.At.Sub(first.At).Seconds()
	if elapsed <= 0 || last.AllocBytes < first.AllocBytes {
		return 0
	}

	return float64(last.AllocBytes-first.AllocBytes) / elapsed
}

// cpuClassesOver returns user and GC CPU across the window, each as a
// percentage of one core.
func cpuClassesOver(samples []statSample) (user, gc, scavenge float64) {
	if len(samples) < 2 {
		return 0, 0, 0
	}

	first, last := samples[0], samples[len(samples)-1]

	elapsed := last.At.Sub(first.At).Seconds()
	if elapsed <= 0 {
		return 0, 0, 0
	}

	return (last.UserSeconds - first.UserSeconds) / elapsed * 100,
		(last.GCSeconds - first.GCSeconds) / elapsed * 100,
		(last.ScavengeSeconds - first.ScavengeSeconds) / elapsed * 100
}
