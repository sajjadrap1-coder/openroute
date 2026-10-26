package policy

import "testing"

func TestSuffixBoundaryAndLongest(t *testing.T) {
	c := Config{DefaultRoute: "direct", Modes: map[string][]Rule{"gaming": {
		{Suffix: "example.com", Route: "peer", Reason: "default peer"},
		{Suffix: "play.example.com", Route: "direct", Reason: "low latency"},
	}}}
	tests := []struct{ host, route string }{
		{"example.com", "peer"}, {"WWW.Example.COM.", "peer"},
		{"play.example.com", "direct"}, {"evil-example.com", "direct"},
	}
	for _, tt := range tests {
		got, err := c.Decide(tt.host, "gaming")
		if err != nil || got.Route != tt.route {
			t.Fatalf("%s: %+v %v", tt.host, got, err)
		}
	}
}
func TestRejectInvalid(t *testing.T) {
	c := Config{}
	for _, h := range []string{"https://example.com", "example.com/evil", "example..org", "bad host"} {
		if _, err := c.Decide(h, "smart"); err == nil {
			t.Fatal(h)
		}
	}
	if _, err := c.Decide("example.org", "invalid"); err == nil {
		t.Fatal("unsupported mode accepted")
	}
}
