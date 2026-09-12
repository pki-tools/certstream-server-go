package config

import "testing"

func validBase() *Config {
	var c Config
	c.Webserver.ListenAddr = "127.0.0.1"
	c.Webserver.ListenPort = 8080
	c.Webserver.FullURL = "/full-stream"
	c.Webserver.LiteURL = "/"
	c.Webserver.DomainsOnlyURL = "/domains-only"

	return &c
}

// TestUIListenerDefaultsToWebsocketInterface checks that only the port normally
// needs setting when splitting the web UI onto its own listener.
func TestUIListenerDefaultsToWebsocketInterface(t *testing.T) {
	c := validBase()
	c.Webserver.UI.Enabled = true
	c.Webserver.UI.ListenPort = 8081

	if !validateConfig(c) {
		t.Fatal("config rejected")
	}

	if got := c.Webserver.UI.ListenAddr; got != "127.0.0.1" {
		t.Errorf("UI listen addr = %q, want it inherited from the websocket listener", got)
	}
	if !c.Webserver.UI.Enabled {
		t.Error("UI listener was disabled unexpectedly")
	}
}

// TestUIListenerOnSameAddressIsFoldedBack guards the misconfiguration where the
// UI is pointed at the port already serving websockets. Starting a second
// listener there would fail to bind, so validation collapses it back onto one.
func TestUIListenerOnSameAddressIsFoldedBack(t *testing.T) {
	c := validBase()
	c.Webserver.UI.Enabled = true
	c.Webserver.UI.ListenAddr = "127.0.0.1"
	c.Webserver.UI.ListenPort = 8080

	if !validateConfig(c) {
		t.Fatal("config rejected")
	}

	if c.Webserver.UI.Enabled {
		t.Error("UI listener sharing the websocket address should have been folded back onto one listener")
	}
}

// A different interface on the same port number is a genuine second listener.
func TestUIListenerOnDifferentInterfaceIsKept(t *testing.T) {
	c := validBase()
	c.Webserver.UI.Enabled = true
	c.Webserver.UI.ListenAddr = "127.0.0.2"
	c.Webserver.UI.ListenPort = 8080

	if !validateConfig(c) {
		t.Fatal("config rejected")
	}

	if !c.Webserver.UI.Enabled {
		t.Error("UI listener on a different interface should have been kept")
	}
}

func TestUIListenerDisabledByDefault(t *testing.T) {
	c := validBase()

	if !validateConfig(c) {
		t.Fatal("config rejected")
	}

	if c.Webserver.UI.Enabled {
		t.Error("UI listener must stay off unless explicitly enabled")
	}
}
