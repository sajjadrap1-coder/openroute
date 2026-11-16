package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// PathComparison compares direct and local SOCKS5 TCP connection establishment.
// Neither value represents actual in-game UDP round-trip time.
type PathComparison struct {
	Target         string    `json:"target"`
	Proxy          string    `json:"proxy"`
	Direct         TCPResult `json:"direct"`
	SOCKS5         TCPResult `json:"socks5"`
	Recommendation string    `json:"recommendation"`
	Note           string    `json:"note"`
}

// ComparePaths alternates direct TCP connects with a local SOCKS5 CONNECT.
func ComparePaths(host string, port int, proxy string, count int, timeout time.Duration) (PathComparison, error) {
	if strings.TrimSpace(host) == "" || strings.ContainsAny(host, "/\\ \t\r\n") {
		return PathComparison{}, errors.New("invalid host")
	}
	if port < 1 || port > 65535 {
		return PathComparison{}, errors.New("invalid port")
	}
	if count < 1 || count > 30 {
		return PathComparison{}, errors.New("count must be between 1 and 30")
	}
	if timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return PathComparison{}, errors.New("timeout must be between 100ms and 30s")
	}
	proxyHost, proxyPort, err := net.SplitHostPort(proxy)
	if err != nil {
		return PathComparison{}, fmt.Errorf("invalid SOCKS5 address: %w", err)
	}
	ip := net.ParseIP(proxyHost)
	if ip == nil || !ip.IsLoopback() {
		return PathComparison{}, errors.New("SOCKS5 proxy must be on localhost")
	}
	n, err := strconv.Atoi(proxyPort)
	if err != nil || n < 1 || n > 65535 {
		return PathComparison{}, errors.New("invalid SOCKS5 port")
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	directTimes, proxyTimes := make([]float64, 0, count), make([]float64, 0, count)
	d := &net.Dialer{Timeout: timeout}
	for i := 0; i < count; i++ {
		trials := []string{"direct", "socks5"}
		if i%2 == 1 {
			trials[0], trials[1] = trials[1], trials[0]
		}
		for _, path := range trials {
			t0 := time.Now()
			var conn net.Conn
			var probeErr error
			if path == "direct" {
				conn, probeErr = d.Dial("tcp", target)
			} else {
				conn, probeErr = dialLocalSocks5(proxy, host, port, timeout)
			}
			ms := float64(time.Since(t0).Microseconds()) / 1000
			if conn != nil {
				_ = conn.Close()
			}
			if probeErr == nil {
				if path == "direct" {
					directTimes = append(directTimes, ms)
				} else {
					proxyTimes = append(proxyTimes, ms)
				}
			}
		}
	}
	a, b := Summarize(target, count, directTimes), Summarize(target, count, proxyTimes)
	a.Transport = "direct TCP connect"
	b.Transport = "SOCKS5 TCP CONNECT (local proxy + remote destination)"
	a.Note = "TCP connection setup only. Does not measure game UDP RTT or sustained throughput."
	b.Note = "Includes SOCKS5 handshake and remote CONNECT; not a game RTT or a VLESS hop-count measurement."
	c := PathComparison{
		Target: target, Proxy: proxy, Direct: a, SOCKS5: b,
		Note: "Selection advisory only. OpenRoute does not change OS routing, BGP, ISP hops, or proxy configuration. Compare from the same device and to the actual service endpoint.",
	}
	switch {
	case a.Successes == 0 && b.Successes == 0:
		c.Recommendation = "neither path established; investigate destination/ISP/proxy"
	case a.Successes == 0:
		c.Recommendation = "SOCKS5 appears usable for this TCP endpoint; direct failed"
	case b.Successes == 0:
		c.Recommendation = "direct TCP is usable; SOCKS5 was unavailable or failed"
	case a.FailurePercent+20 < b.FailurePercent:
		c.Recommendation = "direct TCP is more reliable in this sample"
	case b.FailurePercent+20 < a.FailurePercent:
		c.Recommendation = "SOCKS5 TCP is more reliable in this sample"
	case a.MedianMS+10 < b.MedianMS:
		c.Recommendation = "direct TCP is faster in this sample; keep direct path if accessible"
	case b.MedianMS+10 < a.MedianMS:
		c.Recommendation = "SOCKS5 TCP is faster in this sample; confirm sustained latency"
	default:
		c.Recommendation = "no meaningful TCP setup latency difference; assess jitter/UDP separately"
	}
	return c, nil
}

func dialLocalSocks5(proxy, host string, port int, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxy, timeout)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	if buf[0] != 5 || buf[1] != 0 {
		return nil, errors.New("SOCKS5 proxy does not accept no-auth")
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 1)
			request = append(request, v4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("SOCKS5 hostname exceeds 255 bytes")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	request = append(request, p...)
	if _, err := c.Write(request); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 5 || hdr[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 CONNECT refused (code %d)", hdr[1])
	}
	size := 0
	switch hdr[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		one := []byte{0}
		if _, err := io.ReadFull(c, one); err != nil {
			return nil, err
		}
		size = int(one[0])
	default:
		return nil, errors.New("invalid SOCKS5 reply address type")
	}
	if _, err := io.CopyN(io.Discard, c, int64(size+2)); err != nil {
		return nil, err
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return c, nil
}
