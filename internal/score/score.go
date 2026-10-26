package score

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
)

// PeerMetrics are illustrative measurements supplied locally by the operator.
// Never trust unverified metrics advertised by an unknown remote peer.
type PeerMetrics struct {
	ID             string  `json:"id"`
	LatencyMS      float64 `json:"latency_ms"`
	JitterMS       float64 `json:"jitter_ms"`
	LossPercent    float64 `json:"loss_percent"`
	ThroughputMbps float64 `json:"throughput_mbps"`
}
type RankedPeer struct {
	PeerMetrics
	Score float64 `json:"score"`
}

func ReadFile(path string) ([]PeerMetrics, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var peers []PeerMetrics
	if err = json.Unmarshal(b, &peers); err != nil {
		return nil, err
	}
	return peers, nil
}
func Rank(peers []PeerMetrics, mode string) ([]RankedPeer, error) {
	if mode != "gaming" && mode != "smart" && mode != "ai" {
		return nil, fmt.Errorf("unsupported mode %q", mode)
	}
	result := make([]RankedPeer, 0, len(peers))
	for _, p := range peers {
		if p.ID == "" || !valid(p.LatencyMS) || !valid(p.JitterMS) || !valid(p.LossPercent) || !valid(p.ThroughputMbps) || p.LossPercent > 100 {
			return nil, fmt.Errorf("invalid metrics for peer %q", p.ID)
		}
		// Lower is better; score is a heuristic for candidate ordering, not a throughput or ping guarantee.
		penalty := p.LatencyMS + 2*p.JitterMS + 25*p.LossPercent
		if mode == "gaming" {
			penalty = p.LatencyMS + 4*p.JitterMS + 40*p.LossPercent
		}
		if mode == "ai" {
			penalty = p.LatencyMS*.5 + 2*p.JitterMS + 30*p.LossPercent
		}
		// Penalize bandwidth-constrained relays; weight differs by profile.
		throughputTarget := 10.0
		if mode == "ai" {
			throughputTarget = 20
		}
		if mode == "gaming" {
			throughputTarget = 3
		}
		if p.ThroughputMbps < throughputTarget {
			penalty += 20 * (throughputTarget - p.ThroughputMbps) / throughputTarget
		}
		result = append(result, RankedPeer{PeerMetrics: p, Score: math.Round(penalty*100) / 100})
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Score == result[j].Score {
			return result[i].ID < result[j].ID
		}
		return result[i].Score < result[j].Score
	})
	return result, nil
}
func valid(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 }
