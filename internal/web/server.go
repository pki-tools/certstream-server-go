package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	"github.com/gorilla/websocket"
)

var (
	ClientHandler = BroadcastManager{}
	upgrader      websocket.Upgrader
)

// WebServer is a struct that holds the necessary information to run a webserver.
// It is used for the websocket server as well as the metrics server.
type WebServer struct {
	networkIf string
	port      int
	routes    *chi.Mux
	server    *http.Server
	certPath  string
	keyPath   string
}

// RegisterHTTPHandler registers a plain HTTP handler at the given path on the webserver.
func (ws *WebServer) RegisterHTTPHandler(pattern string, handler http.HandlerFunc) {
	ws.routes.HandleFunc(pattern, handler)
}

// RegisterPrometheus registers a new handler that listens on the given url and calls the given function
// in order to provide metrics for a prometheus server. This function signature was used, because VictoriaMetrics
// offers exactly this function signature.
func (ws *WebServer) RegisterPrometheus(url string, callback func(w io.Writer, exposeProcessMetrics bool)) {
	ws.routes.HandleFunc(url, func(w http.ResponseWriter, _ *http.Request) {
		callback(w, config.AppConfig.Prometheus.ExposeSystemMetrics)
	})
}

// ClientIP returns the address of the client making r, or nil if it cannot be
// determined.
//
// r.RemoteAddr is normally "ip:port", but chi's RealIP middleware - which
// real_ip enables - replaces it with the bare IP taken from X-Forwarded-For or
// a similar header. Parsing it only with net.SplitHostPort, as the whitelist
// used to, fails on that bare form: behind a reverse proxy with real_ip and a
// whitelist both set, every request was answered 500 Internal Server Error.
func ClientIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	return net.ParseIP(host)
}

// IPAllowList matches client addresses against a set of IPs and CIDRs.
type IPAllowList struct {
	ips  []net.IP
	nets []net.IPNet
}

// NewIPAllowList parses entries, returning those it could not parse.
func NewIPAllowList(entries []string) (*IPAllowList, []string) {
	l := &IPAllowList{}

	var invalid []string

	for _, entry := range entries {
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			l.nets = append(l.nets, *ipNet)
			continue
		}

		if ip := net.ParseIP(entry); ip != nil {
			l.ips = append(l.ips, ip)
			continue
		}

		invalid = append(invalid, entry)
	}

	return l, invalid
}

// Empty reports whether the list admits nothing.
func (l *IPAllowList) Empty() bool {
	return l == nil || (len(l.ips) == 0 && len(l.nets) == 0)
}

// Contains reports whether ip is in the list. A nil ip is never contained.
func (l *IPAllowList) Contains(ip net.IP) bool {
	if l == nil || ip == nil {
		return false
	}

	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}

	for _, allowed := range l.ips {
		if allowed.Equal(ip) {
			return true
		}
	}

	return false
}

// IPWhitelist returns a middleware that checks if the IP of the client is in the whitelist.
func IPWhitelist(whitelist []string) func(next http.Handler) http.Handler {
	log.Println("Building IP whitelist...")

	allow, invalid := NewIPAllowList(whitelist)
	for _, entry := range invalid {
		log.Println("Invalid IP in whitelist: ", entry)
	}

	log.Println("IP whitelist: ", allow.ips)
	log.Println("CIDR whitelist: ", allow.nets)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// if the whitelist is empty, just continue
			if allow.Empty() {
				next.ServeHTTP(w, r)
				return
			}

			if allow.Contains(ClientIP(r)) {
				next.ServeHTTP(w, r)
				return
			}

			log.Printf("IP %s not in whitelist, rejecting request\n", r.RemoteAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

// initFullWebsocket is called when a client connects to the /full-stream endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initFullWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		if isWebSocketRequest(r) {
			log.Println("Error while trying to upgrade connection:", err)
		}
		return
	}

	setupClient(connection, SubTypeFull, r.RemoteAddr)
}

// initLiteWebsocket is called when a client connects to the / endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initLiteWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		if isWebSocketRequest(r) {
			log.Println("Error while trying to upgrade connection:", err)
		}
		return
	}

	setupClient(connection, SubTypeLite, r.RemoteAddr)
}

// initDomainWebsocket is called when a client connects to the /domains-only endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initDomainWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		if isWebSocketRequest(r) {
			log.Println("Error while trying to upgrade connection:", err)
		}
		return
	}

	setupClient(connection, SubTypeDomain, r.RemoteAddr)
}

// isWebSocketRequest returns true if the request carries the headers required
// to upgrade to a WebSocket connection (Connection: Upgrade + Upgrade: websocket).
// Checking this before calling upgrader.Upgrade avoids a noisy error log for
// plain HTTP probes (health checks, load-balancer pings, browser navigation).
func isWebSocketRequest(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// upgradeConnection upgrades the connection to a websocket and returns the connection.
func upgradeConnection(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	if !isWebSocketRequest(r) {
		http.Error(w, "This endpoint requires a WebSocket connection (Upgrade: websocket).", http.StatusUpgradeRequired)
		return nil, fmt.Errorf("not a websocket request from %s", r.RemoteAddr)
	}

	var remoteAddr string

	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		remoteAddr = fmt.Sprintf("'%s' (X-Forwarded-For: '%s')", r.RemoteAddr, xForwardedFor)
	} else {
		remoteAddr = fmt.Sprintf("'%s'", r.RemoteAddr)
	}

	log.Printf("Starting new websocket for %s - %s\n", remoteAddr, r.URL)

	connection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}

	defaultCloseHandler := connection.CloseHandler()
	connection.SetCloseHandler(func(code int, text string) error {
		log.Printf("Stopping websocket for %s - %s\n", remoteAddr, r.URL)
		return defaultCloseHandler(code, text)
	})

	return connection, nil
}

// setupClient initializes a client struct and starts the broadcastHandler and websocket listener.
func setupClient(connection *websocket.Conn, subscriptionType SubscriptionType, name string) {
	c := newClient(connection, subscriptionType, name, config.AppConfig.General.BufferSizes.Websocket)
	go c.broadcastHandler()
	go c.listenWebsocket()

	ClientHandler.registerClient(c)
}

// setupWebsocketRoutes configures all the routes necessary for the websocket webserver.
func setupWebsocketRoutes(r *chi.Mux) {
	r.Use(middleware.Recoverer)
	r.Route("/", func(r chi.Router) {
		r.Route(config.AppConfig.Webserver.FullURL, func(r chi.Router) {
			r.HandleFunc("/", initFullWebsocket)
			r.HandleFunc("/example.json", exampleFull)
		})

		r.Route(config.AppConfig.Webserver.LiteURL, func(r chi.Router) {
			r.HandleFunc("/", initLiteWebsocket)
			r.HandleFunc("/example.json", exampleLite)
		})

		r.Route(config.AppConfig.Webserver.DomainsOnlyURL, func(r chi.Router) {
			r.HandleFunc("/", initDomainWebsocket)
			r.HandleFunc("/example.json", exampleDomains)
		})
	})
}

func (ws *WebServer) initServer() {
	addr := net.JoinHostPort(ws.networkIf, strconv.Itoa(ws.port))

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256, tls.X25519},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	ws.server = &http.Server{
		Addr:              addr,
		Handler:           ws.routes,
		TLSConfig:         tlsConfig,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
}

// NewMetricsServer creates a new webserver that listens on the given port and provides metrics for a metrics server.
func NewMetricsServer(networkIf string, port int, certPath, keyPath string) *WebServer {
	server := &WebServer{
		networkIf: networkIf,
		port:      port,
		routes:    chi.NewRouter(),
		certPath:  certPath,
		keyPath:   keyPath,
	}
	server.routes.Use(middleware.Recoverer)

	if config.AppConfig.Prometheus.RealIP {
		server.routes.Use(middleware.RealIP)
	}

	// Enable IP whitelist if configured
	if len(config.AppConfig.Prometheus.Whitelist) > 0 {
		server.routes.Use(IPWhitelist(config.AppConfig.Prometheus.Whitelist))
	}

	server.initServer()

	return server
}

// NewUIServer creates a plain HTTP webserver for the HTML dashboards and the
// health endpoint, with no websocket routes. Running these on their own port
// lets a reverse proxy apply ordinary HTTP timeouts and health checks to them,
// separately from the long-lived websocket connections.
func NewUIServer(cfg config.ServerConfig) *WebServer {
	server := &WebServer{
		networkIf: cfg.ListenAddr,
		port:      cfg.ListenPort,
		routes:    chi.NewRouter(),
		certPath:  cfg.CertPath,
		keyPath:   cfg.CertKeyPath,
	}

	server.routes.Use(middleware.Recoverer)

	if cfg.RealIP {
		server.routes.Use(middleware.RealIP)
	}

	if len(cfg.Whitelist) > 0 {
		server.routes.Use(IPWhitelist(cfg.Whitelist))
	}

	server.initServer()

	return server
}

// NewWebsocketServer starts a new webserver and initialized it with the necessary routes.
// It also starts the broadcaster in ClientHandler as a background job and takes care of
// setting up websocket.Upgrader.
func NewWebsocketServer(networkIf string, port int, certPath, keyPath string) *WebServer {
	server := &WebServer{
		networkIf: networkIf,
		port:      port,
		routes:    chi.NewRouter(),
		certPath:  certPath,
		keyPath:   keyPath,
	}

	upgrader = websocket.Upgrader{
		EnableCompression: config.AppConfig.Webserver.CompressionEnabled,
		CheckOrigin: func(_ *http.Request) bool {
			// Allow all connections by default
			return true
		},
	}

	if config.AppConfig.Webserver.RealIP {
		server.routes.Use(middleware.RealIP)
	}

	// Enable IP whitelist if configured
	if len(config.AppConfig.Webserver.Whitelist) > 0 {
		server.routes.Use(IPWhitelist(config.AppConfig.Webserver.Whitelist))
	}

	setupWebsocketRoutes(server.routes)
	server.initServer()

	startBroadcaster()

	return server
}

// broadcasterOnce guards the process-wide broadcast channel and its goroutine.
var broadcasterOnce sync.Once

// startBroadcaster creates ClientHandler's broadcast channel and starts its
// dispatch goroutine, exactly once per process.
//
// ClientHandler is a package-level singleton, but this used to run on every
// NewWebsocketServer call: each call replaced ClientHandler.Broadcast - a data
// race with the broadcaster already reading that field, and with certHandler
// sending on it - and started another broadcaster that was never stopped. A
// process builds one server, so this was latent in production, but it is what
// the race detector caught in tests that build several.
func startBroadcaster() {
	broadcasterOnce.Do(func() {
		ClientHandler.Broadcast = make(chan models.Entry, config.AppConfig.General.BufferSizes.BroadcastManager)
		go ClientHandler.broadcaster()
	})
}

// Start initializes the webserver and starts listening for connections.
func (ws *WebServer) Start() {
	log.Printf("Starting webserver on %s\n", ws.server.Addr)

	var err error
	if ws.keyPath != "" && ws.certPath != "" {
		err = ws.server.ListenAndServeTLS(ws.certPath, ws.keyPath)
	} else {
		err = ws.server.ListenAndServe()
	}

	// Shutdown makes ListenAndServe return ErrServerClosed. That is the normal
	// end of a graceful stop, not a failure — treating it as fatal would exit
	// non-zero on a clean SIGTERM and look like a crash to the supervisor.
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("Error while serving webserver: ", err)
	}

	log.Printf("Stopped webserver on %s\n", ws.server.Addr)
}

// Stop tries to stop the webserver gracefully. If it doesn't stop within 15 seconds, it is forcefully closed.
func (ws *WebServer) Stop() {
	log.Println("Stopping webserver...")

	// If the server did not stop within 15 seconds, forcefully close it
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := ws.server.Shutdown(ctx); err != nil {
		log.Fatal("Error while stopping webserver: ", err)
	}
}
