package probe

import (
	"math"
	"testing"
)

func TestSummarize(t *testing.T) {
	r := Summarize("example.org:443", 5, []float64{20, 30, 10, 40})
	if r.Successes != 4 || r.Failures != 1 || r.FailurePercent != 20 || r.MinMS != 10 || r.MedianMS != 25 {
		t.Fatalf("unexpected summary: %+v", r)
	}
	if math.Abs(r.MeanMS-25) > 0.001 {
		t.Fatalf("mean: %v", r.MeanMS)
	}
	if math.Abs(r.P95MS-38.5) > 0.001 {
		t.Fatalf("p95: %v", r.P95MS)
	}
}
func TestNoSamples(t *testing.T) {
	r := Summarize("localhost:9", 2, nil)
	if r.Failures != 2 || r.MedianMS != 0 {
		t.Fatal(r)
	}
}
