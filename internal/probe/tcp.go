package probe

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

type TCPResult struct {
	Transport      string    `json:"transport"`
	Target         string    `json:"target"`
	Attempts       int       `json:"attempts"`
	Successes      int       `json:"successes"`
	Failures       int       `json:"failures"`
	FailurePercent float64   `json:"failure_percent"`
	MinMS          float64   `json:"min_ms"`
	MedianMS       float64   `json:"median_ms"`
	P95MS          float64   `json:"p95_ms"`
	MeanMS         float64   `json:"mean_ms"`
	StdDevMS       float64   `json:"std_dev_ms"`
	SamplesMS      []float64 `json:"samples_ms"`
	Errors         []string  `json:"errors,omitempty"`
	Note           string    `json:"note"`
}

func TCP(host string, port, count int, timeout time.Duration) (TCPResult, error) {
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "/\\") {
		return TCPResult{}, fmt.Errorf("invalid host")
	}
	if port < 1 || port > 65535 {
		return TCPResult{}, fmt.Errorf("port must be 1-65535")
	}
	if count < 1 || count > 100 {
		return TCPResult{}, fmt.Errorf("count must be 1-100")
	}
	if timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return TCPResult{}, fmt.Errorf("timeout must be 100ms-30s")
	}
	target := net.JoinHostPort(host, fmt.Sprint(port))
	samples := make([]float64, 0, count)
	errs := make([]string, 0)
	d := &net.Dialer{Timeout: timeout}
	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := d.Dial("tcp", target)
		took := float64(time.Since(start).Microseconds()) / 1000
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		_ = conn.Close()
		samples = append(samples, took)
	}
	r := Summarize(target, count, samples)
	// Limit error exposure (host/IP metadata may be sensitive).
	for _, s := range errs {
		if len(r.Errors) >= 3 {
			break
		}
		if len(s) > 200 {
			s = s[:200]
		}
		r.Errors = append(r.Errors, s)
	}
	return r, nil
}

func Summarize(target string, attempts int, samples []float64) TCPResult {
	s := append([]float64(nil), samples...)
	sort.Float64s(s)
	r := TCPResult{Transport: "TCP connect", Target: target, Attempts: attempts, Successes: len(s), Failures: attempts - len(s), SamplesMS: samples,
		Note: "TCP connection setup only; excludes ICMP RTT, UDP game latency, throughput, route security, and HTTP response time."}
	if attempts > 0 {
		r.FailurePercent = 100 * float64(r.Failures) / float64(attempts)
	}
	if len(s) == 0 {
		return r
	}
	r.MinMS = s[0]
	r.MedianMS = quantile(s, 0.5)
	r.P95MS = quantile(s, 0.95)
	for _, x := range s {
		r.MeanMS += x
	}
	r.MeanMS /= float64(len(s))
	for _, x := range s {
		r.StdDevMS += (x - r.MeanMS) * (x - r.MeanMS)
	}
	r.StdDevMS = math.Sqrt(r.StdDevMS / float64(len(s)))
	return r
}

func quantile(s []float64, q float64) float64 {
	if len(s) == 1 {
		return s[0]
	}
	pos := q * float64(len(s)-1)
	i := int(math.Floor(pos))
	return s[i] + (s[i+1]-s[i])*(pos-float64(i))
}
