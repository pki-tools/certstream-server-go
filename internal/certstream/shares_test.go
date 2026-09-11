package certstream

import (
	"math"
	"testing"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
)

func status(name, operator string, rate float64) certificatetransparency.LogStatusSnapshot {
	return certificatetransparency.LogStatusSnapshot{
		URL: name, Name: name, Operator: operator, Type: "Regular", RatePerSec: rate,
	}
}

func TestBuildSharesAccountsForWholeStream(t *testing.T) {
	statuses := []certificatetransparency.LogStatusSnapshot{
		status("oak-a", "Let's Encrypt", 500),
		status("oak-b", "Let's Encrypt", 300),
		status("argon", "Google", 150),
		status("xenon", "Google", 50),
		status("nimbus", "Cloudflare", 100),
		// Idle logs must not dilute the percentages.
		status("idle-1", "Sectigo", 0),
		status("idle-2", "Sectigo", 0),
	}

	byLog, byOp := buildShares(statuses)

	var logSum, opSum float64
	for _, r := range byLog {
		logSum += r.Percent
	}
	for _, r := range byOp {
		opSum += r.Percent
	}

	if math.Abs(logSum-100) > 0.5 {
		t.Errorf("log shares sum to %.2f%%, want 100%%", logSum)
	}
	if math.Abs(opSum-100) > 0.5 {
		t.Errorf("operator shares sum to %.2f%%, want 100%%", opSum)
	}

	if len(byOp) != 3 {
		t.Fatalf("got %d operators, want 3 (idle operator excluded)", len(byOp))
	}

	// Total rate is 1100; Let's Encrypt contributes 800.
	if byOp[0].Name != "Let's Encrypt" {
		t.Errorf("top operator = %q, want Let's Encrypt", byOp[0].Name)
	}
	if want := 800.0 / 1100 * 100; math.Abs(byOp[0].Percent-want) > 0.1 {
		t.Errorf("top operator share = %.2f%%, want %.2f%%", byOp[0].Percent, want)
	}
	if byOp[0].Logs != 2 {
		t.Errorf("top operator log count = %d, want 2", byOp[0].Logs)
	}
}

// TestTopSharesFoldsRemainderIntoOther guards the property that makes the chart
// honest: nothing is silently dropped, so the slices always total 100%.
func TestTopSharesFoldsRemainderIntoOther(t *testing.T) {
	var rows []shareRow
	var total float64
	for i := 0; i < 20; i++ {
		rate := float64(20 - i)
		rows = append(rows, shareRow{Name: "log", Rate: rate, Logs: 1})
		total += rate
	}

	out := topShares(rows, total, 8)

	if len(out) != 9 {
		t.Fatalf("got %d rows, want 8 + Other", len(out))
	}
	if out[len(out)-1].Name != "Other" {
		t.Errorf("last row = %q, want Other", out[len(out)-1].Name)
	}
	if got := out[len(out)-1].Logs; got != 12 {
		t.Errorf("Other folds %d logs, want 12", got)
	}

	var sum float64
	for _, r := range out {
		sum += r.Percent
	}
	if math.Abs(sum-100) > 0.5 {
		t.Errorf("shares sum to %.2f%%, want 100%%", sum)
	}
}

func TestBuildSharesWithNoTraffic(t *testing.T) {
	byLog, byOp := buildShares([]certificatetransparency.LogStatusSnapshot{
		status("idle", "Nobody", 0),
	})

	if byLog != nil || byOp != nil {
		t.Errorf("expected no rows when nothing is flowing, got %d/%d", len(byLog), len(byOp))
	}
}
