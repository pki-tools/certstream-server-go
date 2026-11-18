package certstream

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func extractTile(body string) string {
	i := strings.Index(body, "Chain cache")
	if i < 0 {
		return "(tile not found)"
	}

	end := i + 300
	if end > len(body) {
		end = len(body)
	}

	return body[i:end]
}
