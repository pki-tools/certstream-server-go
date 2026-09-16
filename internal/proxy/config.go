// Package proxy implements a small authenticated CONNECT proxy, used to fetch
// from CT logs via a different egress address than the main server.
package proxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the standalone proxy's configuration file.
type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`

	// AuthToken must be presented by callers as
	// "Proxy-Authorization: Bearer <token>". Required.
	AuthToken string `yaml:"auth_token"`

	// TLS optionally wraps the proxy hop itself. Without it the token travels in
	// plaintext, so it should be set unless the hop is already private.
	TLS struct {
		CertPath string `yaml:"cert_path"`
		KeyPath  string `yaml:"key_path"`
	} `yaml:"tls"`

	// AllowedIPs restricts which source addresses may connect, as IPs or CIDRs.
	// Empty means any source may connect, relying on the token alone.
	AllowedIPs []string `yaml:"allowed_ips"`

	// AllowedHosts restricts which destinations may be reached. An entry
	// beginning with "." matches any subdomain of it; otherwise it must match the
	// hostname exactly. Empty denies everything: this is the control that stops a
	// leaked token turning the proxy into an open relay, so it fails closed.
	AllowedHosts []string `yaml:"allowed_hosts"`

	// AllowedPorts restricts destination ports. Defaults to 443 only.
	AllowedPorts []int `yaml:"allowed_ports"`

	DialTimeout    time.Duration `yaml:"dial_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	MaxConnections int           `yaml:"max_connections"`

	// allowedNets is the parsed form of AllowedIPs.
	allowedNets []*net.IPNet
}

// LoadConfig reads and validates the proxy configuration.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading proxy config: %w", err)
	}

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing proxy config: %w", err)
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *Config) validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0"
	}

	if c.ListenPort == 0 {
		c.ListenPort = 8443
	}

	if strings.TrimSpace(c.AuthToken) == "" {
		return errors.New("auth_token is required: without it anyone reaching the port could use the proxy")
	}

	if len(c.AuthToken) < 16 {
		return errors.New("auth_token must be at least 16 characters")
	}

	if len(c.AllowedHosts) == 0 {
		return errors.New("allowed_hosts is empty, which would deny every request: list the CT log hostnames this proxy may reach")
	}

	if len(c.AllowedPorts) == 0 {
		c.AllowedPorts = []int{443}
	}

	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}

	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 2 * time.Minute
	}

	if c.MaxConnections <= 0 {
		c.MaxConnections = 512
	}

	if (c.TLS.CertPath == "") != (c.TLS.KeyPath == "") {
		return errors.New("tls.cert_path and tls.key_path must be set together")
	}

	for _, entry := range c.AllowedIPs {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			ip := net.ParseIP(entry)
			if ip == nil {
				return fmt.Errorf("allowed_ips contains %q, which is neither an IP nor a CIDR", entry)
			}

			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}

		c.allowedNets = append(c.allowedNets, network)
	}

	return nil
}

// sourceAllowed reports whether a connection from addr may use the proxy.
func (c *Config) sourceAllowed(addr net.IP) bool {
	if len(c.allowedNets) == 0 {
		return true
	}

	for _, n := range c.allowedNets {
		if n.Contains(addr) {
			return true
		}
	}

	return false
}

// hostAllowed reports whether host may be reached through the proxy. A pattern
// starting with "." matches the domain and any subdomain of it.
func (c *Config) hostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	for _, pattern := range c.AllowedHosts {
		pattern = strings.ToLower(pattern)

		if strings.HasPrefix(pattern, ".") {
			if strings.HasSuffix(host, pattern) || host == strings.TrimPrefix(pattern, ".") {
				return true
			}

			continue
		}

		if host == pattern {
			return true
		}
	}

	return false
}

func (c *Config) portAllowed(port int) bool {
	for _, p := range c.AllowedPorts {
		if p == port {
			return true
		}
	}

	return false
}
