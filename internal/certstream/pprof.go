package certstream

import (
	"net/http"
	"net/http/pprof"

	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

// registerPprof exposes Go's standard profiling endpoints.
//
// Enabled only by general.pprof, and registered on the web UI listener so it
// inherits that listener's IP whitelist. With it on:
//
//	go tool pprof http://host:port/debug/pprof/profile?seconds=30
//
// gives a CPU profile showing exactly which functions the time goes to, which
// is the tool to reach for once /system says the process is CPU-bound.
func registerPprof(server *web.WebServer) {
	server.RegisterHTTPHandler("/debug/pprof/", pprof.Index)
	server.RegisterHTTPHandler("/debug/pprof/cmdline", pprof.Cmdline)
	server.RegisterHTTPHandler("/debug/pprof/profile", pprof.Profile)
	server.RegisterHTTPHandler("/debug/pprof/symbol", pprof.Symbol)
	server.RegisterHTTPHandler("/debug/pprof/trace", pprof.Trace)

	// The runtime's named profiles (heap, goroutine, allocs, block, mutex) are
	// all served by Index, but registering them directly keeps the links on the
	// index page working when it is mounted at a non-root path.
	for _, name := range []string{"heap", "goroutine", "allocs", "block", "mutex", "threadcreate"} {
		server.RegisterHTTPHandler("/debug/pprof/"+name, func(w http.ResponseWriter, r *http.Request) {
			pprof.Handler(name).ServeHTTP(w, r)
		})
	}
}
