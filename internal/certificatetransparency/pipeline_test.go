package certificatetransparency

import (
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

// runCertHandler feeds entries through the real certHandler and returns how much
// time it attributed to each stage.
func runCertHandler(t *testing.T, broadcastCap int, feed func(chan<- models.Entry)) PipelineTiming {
	t.Helper()

	before := GetPipelineTiming()

	web.ClientHandler.Broadcast = make(chan models.Entry, broadcastCap)
	entryChan := make(chan models.Entry, 8)

	done := make(chan struct{})
	go func() {
		certHandler(entryChan)
		close(done)
	}()

	feed(entryChan)
	close(entryChan)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("certHandler did not exit after its channel closed")
	}

	after := GetPipelineTiming()

	return PipelineTiming{
		WaitIn:  after.WaitIn - before.WaitIn,
		WaitOut: after.WaitOut - before.WaitOut,
		Busy:    after.Busy - before.Busy,
		Handled: after.Handled - before.Handled,
	}
}

// TestCertHandlerAttributesInputWait covers the fetch-bound shape: entries arrive
// slowly and the downstream channel has room, so nearly all the time is spent
// waiting for input.
func TestCertHandlerAttributesInputWait(t *testing.T) {
	got := runCertHandler(t, 64, func(ch chan<- models.Entry) {
		for i := 0; i < 3; i++ {
			time.Sleep(20 * time.Millisecond)
			ch <- models.Entry{}
		}
	})

	if got.Handled != 3 {
		t.Fatalf("handled %d entries, want 3", got.Handled)
	}
	if got.WaitIn < 40*time.Millisecond {
		t.Errorf("WaitIn = %v, expected it to capture the producer delay", got.WaitIn)
	}
	if got.WaitOut > got.WaitIn {
		t.Errorf("WaitOut (%v) exceeded WaitIn (%v); a starved handler should be dominated by input wait",
			got.WaitOut, got.WaitIn)
	}
}

// TestCertHandlerAttributesOutputWait covers the broadcast-bound shape: the
// downstream channel is full, so the handler blocks handing entries on. This is
// the signal that processing rather than downloading is the constraint.
func TestCertHandlerAttributesOutputWait(t *testing.T) {
	// Capacity 1, and nothing drains it, so the second send blocks until the
	// reader below frees a slot.
	var got PipelineTiming

	done := make(chan struct{})
	go func() {
		got = runCertHandler(t, 1, func(ch chan<- models.Entry) {
			for i := 0; i < 3; i++ {
				ch <- models.Entry{}
			}
		})
		close(done)
	}()

	// Drain slowly so the handler is forced to wait on the send.
	go func() {
		for i := 0; i < 3; i++ {
			time.Sleep(25 * time.Millisecond)
			<-web.ClientHandler.Broadcast
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	if got.WaitOut < 20*time.Millisecond {
		t.Errorf("WaitOut = %v, expected the blocked send to be recorded", got.WaitOut)
	}
	if got.WaitOut < got.Busy {
		t.Errorf("WaitOut (%v) should dominate Busy (%v) when the downstream channel is full",
			got.WaitOut, got.Busy)
	}
}
