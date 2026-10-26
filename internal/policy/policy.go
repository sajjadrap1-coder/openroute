package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

type Rule struct {
	Suffix string `json:"suffix"`
	Route  string `json:"route"`
	Reason string `json:"reason"`
}

type Config struct {
	DefaultRoute string            `json:"default_route"`
	Modes        map[string][]Rule `json:"modes"`
}

type Decision struct {
	Host   string `json:"host"`
	Mode   string `json:"mode"`
	Route  string `json:"route"`
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

func ReadFile(filename string) (Config, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err = json.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	if c.DefaultRoute == "" {
		c.DefaultRoute = "direct"
	}
	if !validRoute(c.DefaultRoute) {
		return Config{}, errors.New("invalid default_route")
	}
	for mode, rules := range c.Modes {
		if !validMode(mode) {
			return Config{}, fmt.Errorf("invalid mode %q", mode)
		}
		for _, r := range rules {
			if !validRoute(r.Route) || cleanHost(r.Suffix) == "" {
				return Config{}, fmt.Errorf("invalid rule in mode %q", mode)
			}
		}
	}
	return c, nil
}

func (c Config) Decide(host, mode string) (Decision, error) {
	host = cleanHost(host)
	if host == "" {
		return Decision{}, errors.New("invalid hostname")
	}
	if !validMode(mode) {
		return Decision{}, fmt.Errorf("unsupported mode %q", mode)
	}
	route := c.DefaultRoute
	if route == "" {
		route = "direct"
	}
	decision := Decision{Host: host, Mode: mode, Route: route, Reason: "Default policy", Note: "Routing policy simulation only: no actual traffic is tunneled."}
	if mode == "direct" {
		decision.Route = "direct"
		decision.Reason = "Direct mode"
		return decision, nil
	}
	longest := 0
	for _, rule := range c.Modes[mode] {
		suffix := cleanHost(rule.Suffix)
		if suffix == "" {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			if len(suffix) > longest {
				decision.Route = rule.Route
				decision.Reason = rule.Reason
				longest = len(suffix)
			}
		}
	}
	return decision, nil
}

func validMode(s string) bool  { return s == "gaming" || s == "smart" || s == "ai" || s == "direct" }
func validRoute(s string) bool { return s == "direct" || s == "peer" || s == "block" }

func cleanHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if strings.ContainsAny(host, "/:\\ \t\r\n") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	if len(host) > 253 || len(host) == 0 {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return ""
			}
		}
	}
	return host
}
