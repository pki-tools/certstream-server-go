package certificatetransparency

import (
	"sync/atomic"
	"time"
)

// The entry pipeline runs: per-log fetchers -> certChan -> certHandler ->
// broadcast channel -> broadcaster -> clients.
//
// certHandler sits between the two buffers, so timing how long it waits at each
// end identifies the constraint without attaching a profiler:
//
//	mostly waiting for input -> fetching is the limit (network, config, throttling)
//	mostly blocked on output -> broadcasting is the limit (JSON encoding, slow clients)
//	mostly neither           -> certHandler's own work is the limit
//
// The clock reads cost roughly 100ns per certificate, negligible beside the
// certificate parsing and JSON encoding on either side.
var (
	pipelineWaitIn  atomic.Int64 // ns blocked receiving from certChan
	pipelineWaitOut atomic.Int64 // ns blocked sending to the broadcast channel
	pipelineBusy    atomic.Int64 // ns doing certHandler's own work
	pipelineHandled atomic.Int64
)

// PipelineTiming is the cumulative time certHandler has spent in each state.
type PipelineTiming struct {
	WaitIn  time.Duration
	WaitOut time.Duration
	Busy    time.Duration
	Handled int64
}

// Total returns the combined time across all three states.
func (t PipelineTiming) Total() time.Duration {
	return t.WaitIn + t.WaitOut + t.Busy
}

// GetPipelineTiming returns the cumulative certHandler timings.
func GetPipelineTiming() PipelineTiming {
	return PipelineTiming{
		WaitIn:  time.Duration(pipelineWaitIn.Load()),
		WaitOut: time.Duration(pipelineWaitOut.Load()),
		Busy:    time.Duration(pipelineBusy.Load()),
		Handled: pipelineHandled.Load(),
	}
}

// recordPipelineTiming accumulates one certificate's journey through certHandler.
func recordPipelineTiming(waitIn, waitOut, busy time.Duration) {
	pipelineWaitIn.Add(int64(waitIn))
	pipelineWaitOut.Add(int64(waitOut))
	pipelineBusy.Add(int64(busy))
	pipelineHandled.Add(1)
}
