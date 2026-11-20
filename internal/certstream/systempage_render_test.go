package certstream

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
)

// TestSystemPageRendersChainCache renders the real handler. A template error in
// a tile is only visible here: the status code is written before execution.
func TestSystemPageRendersChainCache(t *testing.T) {
	// Give the cache a known hit ratio: 3 hits out of 4 lookups.
	storeSeed := []byte("issuer-der-bytes")
	certificatetransparency.SeedChainCacheForTest(storeSeed, 3, 1)

	rec := httptest.NewRecorder()
	systemHandler(rec, httptest.NewRequest(http.MethodGet, "/system", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, "Error") && strings.Contains(body, "template") {
		t.Fatalf("template error in body: %s", body)
	}

	if !strings.Contains(body, "Chain cache") {
		t.Error("chain cache tile missing from rendered page")
	}

	if !strings.Contains(body, "75%") {
		t.Errorf("expected hit ratio 75%% in page, got:\n%s", extractTile(body))
	}
}

// TestSystemPageRendersFetchEfficiency renders the fetch table with a log that
// returns 32 of 1000 requested entries. Template errors in the new rows are
// only visible from a real render, since the 200 is written before execution.
func TestSystemPageRendersFetchEfficiency(t *testing.T) {
	certificatetransparency.SeedFetchStatsForTest("https://ct.example.com/log", "capped-log", 1000, 32)

	rec := httptest.NewRecorder()
	systemHandler(rec, httptest.NewRequest(http.MethodGet, "/system", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{"Fetch efficiency", "capped-log", "32.0", "3%"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q\nsection:\n%s", want, section(body, "Fetch efficiency"))
		}
	}
}

func section(body, heading string) string {
	i := strings.Index(body, heading)
	if i < 0 {
		return "(section not found)"
	}

	end := i + 900
	if end > len(body) {
		end = len(body)
	}

	return body[i:end]
}

func extractTile(body string) string {
	i := strings.Index(body, "Chain cache")
	if i < 0 {
		return "(tile not found)"
	}

	end := i + 400
	if end > len(body) {
		end = len(body)
	}

	return body[i:end]
}

// TestSystemPageCPUTileReadsInCores guards the wording that caused a real
// misreading. The tile showed "99% of 2.0 available cores · 199% of one core":
// two percentages on different bases side by side, which reads as a fault when
// both cores being busy is in fact the goal.
//
// Samples are seeded so the tile actually renders - with none, it says
// "not reported on this platform" and asserting on it proves nothing.
func TestSystemPageCPUTileReadsInCores(t *testing.T) {
	// 2.0 CPU-seconds consumed over 1.0 second of wall clock = 2 cores busy.
	seedStatsForTest([]statSample{
		{At: time.Now().Add(-time.Second), CPUSeconds: 10, Processed: 1000},
		{At: time.Now(), CPUSeconds: 12, Processed: 3000},
	})
	defer seedStatsForTest(nil)

	rec := httptest.NewRecorder()
	systemHandler(rec, httptest.NewRequest(http.MethodGet, "/system", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	tile := section(body, "CPU used")
	if tile == "(section not found)" {
		t.Fatal("CPU tile missing")
	}

	if strings.Contains(tile, "not reported") {
		t.Fatalf("seeded samples did not reach the tile:\n%s", tile)
	}

	// The old second percentage must be gone from the tile itself.
	if strings.Contains(tile, "of one core") {
		t.Errorf("CPU tile still shows a percentage of one core:\n%s", tile)
	}

	// 2.00 cores busy, expressed in cores rather than as 200%%.
	if !strings.Contains(tile, "2.00 of") {
		t.Errorf("CPU tile should report cores busy as a core count:\n%s", tile)
	}

	if !strings.Contains(tile, "busy") {
		t.Errorf("CPU tile should say what the figure means:\n%s", tile)
	}
}
