package certificatetransparency

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

// gzipTestServer serves a three-entry get-entries body. It gzips the response
// when the client asks for gzip, or always if alwaysGzip is set - the
// misbehaving case. It records the Accept-Encoding of the last request.
type gzipTestServer struct {
	alwaysGzip bool

	mu             sync.Mutex
	acceptEncoding string
	sentGzip       bool
}

const testEntriesBody = `{"entries":[{"leaf_input":"AA==","extra_data":"AA=="},` +
	`{"leaf_input":"AA==","extra_data":"AA=="},{"leaf_input":"AA==","extra_data":"AA=="}]}`

func (s *gzipTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ae := r.Header.Get("Accept-Encoding")
	gz := s.alwaysGzip || strings.Contains(ae, "gzip")

	s.mu.Lock()
	s.acceptEncoding, s.sentGzip = ae, gz
	s.mu.Unlock()

	if !gz {
		_, _ = io.WriteString(w, testEntriesBody)
		return
	}

	w.Header().Set("Content-Encoding", "gzip")

	zw := gzip.NewWriter(w)
	_, _ = io.WriteString(zw, testEntriesBody)
	_ = zw.Close()
}

func setHTTPCompression(t *testing.T, on bool) {
	t.Helper()

	prev := config.AppConfig.General.Scanner.HTTPCompression
	config.AppConfig.General.Scanner.HTTPCompression = &on

	t.Cleanup(func() { config.AppConfig.General.Scanner.HTTPCompression = prev })
}

// fetchEntries performs one get-entries request through the real log client
// and returns the body as the caller sees it.
func fetchEntries(t *testing.T, srv *httptest.Server) string {
	t.Helper()

	client := NewRateLimitedClient(srv.URL, "gzip-test", 0)

	resp, err := client.Get(srv.URL + "/ct/v1/get-entries?start=0&end=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	return string(body)
}

// TestHTTPCompressionOnByDefault pins the default: gzip is requested and
// decoded transparently, exactly as before the setting existed.
func TestHTTPCompressionOnByDefault(t *testing.T) {
	setHTTPCompression(t, true)

	s := &gzipTestServer{}
	srv := httptest.NewServer(s)
	defer srv.Close()

	if got := fetchEntries(t, srv); got != testEntriesBody {
		t.Fatalf("body = %q, want the decoded JSON", got)
	}

	if !strings.Contains(s.acceptEncoding, "gzip") || !s.sentGzip {
		t.Errorf("Accept-Encoding = %q, sent gzip = %v; want gzip requested and used", s.acceptEncoding, s.sentGzip)
	}
}

// TestHTTPCompressionOff checks the client asks for identity explicitly -
// sending no Accept-Encoding would mean "anything is acceptable" - and gets a
// plain body.
func TestHTTPCompressionOff(t *testing.T) {
	setHTTPCompression(t, false)

	s := &gzipTestServer{}
	srv := httptest.NewServer(s)
	defer srv.Close()

	if got := fetchEntries(t, srv); got != testEntriesBody {
		t.Fatalf("body = %q, want the plain JSON", got)
	}

	if s.acceptEncoding != "identity" {
		t.Errorf("Accept-Encoding = %q, want identity", s.acceptEncoding)
	}

	if s.sentGzip {
		t.Error("server sent gzip although the client asked for identity")
	}
}

// TestHTTPCompressionOffServerGzipsAnyway covers a server that ignores the
// request and gzips regardless. With compression disabled Go's transport no
// longer decodes that, so without our handling the caller would receive gzip
// bytes and fail to parse them. The entry counter must also see plain JSON.
func TestHTTPCompressionOffServerGzipsAnyway(t *testing.T) {
	setHTTPCompression(t, false)
	resetFetchStats()

	s := &gzipTestServer{alwaysGzip: true}
	srv := httptest.NewServer(s)
	defer srv.Close()

	if got := fetchEntries(t, srv); got != testEntriesBody {
		t.Fatalf("body = %q, want gzip from a misbehaving server decoded", got)
	}

	if !s.sentGzip {
		t.Fatal("precondition: the server should have sent gzip")
	}

	stats := GetFetchStats()
	if len(stats) != 1 || stats[0].EntriesPerResponse != 3 {
		t.Errorf("fetch stats = %+v; the entry counter should see the 3 decoded entries", stats)
	}
}
