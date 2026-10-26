package score

import "testing"

func TestGamingPrefersLowLatency(t *testing.T) {
	peers := []PeerMetrics{{ID: "slow", LatencyMS: 120, JitterMS: 15, ThroughputMbps: 100}, {ID: "fast", LatencyMS: 25, JitterMS: 3, ThroughputMbps: 30}}
	ranked, err := Rank(peers, "gaming")
	if err != nil || ranked[0].ID != "fast" {
		t.Fatalf("unexpected rank: %+v %v", ranked, err)
	}
}
func TestInvalidMetrics(t *testing.T) {
	_, err := Rank([]PeerMetrics{{ID: "bad", LossPercent: 200}}, "smart")
	if err == nil {
		t.Fatal("expected metric validation error")
	}
}
