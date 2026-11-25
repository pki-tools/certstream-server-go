package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		remoteAddr string
		want       string
	}{
		{"203.0.113.9:5555", "203.0.113.9"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"203.0.113.9", "203.0.113.9"}, // as chi's RealIP leaves it
		{"2001:db8::1", "2001:db8::1"}, // likewise, IPv6
		{"not-an-ip", ""},
		{"", ""},
	}

	for _, tc := range cases {
		got := ClientIP(&http.Request{RemoteAddr: tc.remoteAddr})

		if tc.want == "" {
			if got != nil {
				t.Errorf("ClientIP(%q) = %v, want nil", tc.remoteAddr, got)
			}

			continue
		}

		if !got.Equal(net.ParseIP(tc.want)) {
			t.Errorf("ClientIP(%q) = %v, want %s", tc.remoteAddr, got, tc.want)
		}
	}
}

func TestIPAllowList(t *testing.T) {
	l, invalid := NewIPAllowList([]string{"203.0.113.9", "10.0.0.0/8", "2001:db8::/32", "nonsense"})

	if len(invalid) != 1 || invalid[0] != "nonsense" {
		t.Errorf("invalid = %v, want [nonsense]", invalid)
	}

	for ip, want := range map[string]bool{
		"203.0.113.9": true, "203.0.113.10": false,
		"10.1.2.3": true, "11.1.2.3": false,
		"2001:db8::5": true, "2001:db9::5": false,
	} {
		if got := l.Contains(net.ParseIP(ip)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", ip, got, want)
		}
	}

	if l.Contains(nil) {
		t.Error("Contains(nil) must be false")
	}

	if empty, _ := NewIPAllowList(nil); !empty.Empty() {
		t.Error("an empty list should report Empty")
	}
}

// TestIPWhitelistBehindProxy is the regression test for whitelists combined
// with real_ip. chi's RealIP rewrites RemoteAddr to a bare IP taken from
// X-Forwarded-For; the whitelist used to parse it with net.SplitHostPort only,
// fail, and answer 500 to every proxied request.
func TestIPWhitelistBehindProxy(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(IPWhitelist([]string{"203.0.113.9"}))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	for _, tc := range []struct {
		xff  string
		want int
	}{
		{"203.0.113.9", http.StatusOK},
		{"198.51.100.1", http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:40000" // the proxy
		req.Header.Set("X-Forwarded-For", tc.xff)

		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != tc.want {
			t.Errorf("X-Forwarded-For %s: status %d, want %d", tc.xff, rec.Code, tc.want)
		}
	}
}
