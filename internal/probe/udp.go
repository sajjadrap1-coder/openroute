package probe

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"time"
)

// The diagnostic protocol is intentionally restricted to consenting endpoints.
// Responses are exactly the same size as authenticated requests: 64 bytes.
// This is NOT a tunnel, game ping measurement, or generic UDP port scanner.
const udpMagic = "OPENRT01"
const udpPacketSize = 64

// UDPMetrics summarize round-trip times to a cooperating OpenRoute peer.
// They are not real in-game RTTs, throughput results, or security assurances.
type UDPMetrics struct {
	TCPResult
	JitterMS float64 `json:"jitter_ms"`
}

func validateUDPToken(token string) error {
	if len(token) < 16 {
		return errors.New("OPENROUTE_UDP_TOKEN must be at least 16 bytes; use a randomly generated value")
	}
	return nil
}

func udpPacket(token string) ([]byte, error) {
	out := make([]byte, udpPacketSize)
	copy(out, []byte(udpMagic))
	if _, err := rand.Read(out[8:24]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint64(out[24:32], uint64(time.Now().UnixNano()))
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(out[:32])
	copy(out[32:], mac.Sum(nil))
	return out, nil
}

func validUDPPacket(packet []byte, token string, now time.Time) bool {
	if len(packet) != udpPacketSize || string(packet[:8]) != udpMagic {
		return false
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(packet[:32])
	if !hmac.Equal(packet[32:], mac.Sum(nil)) {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(packet[24:32]))
	age := now.Sub(time.Unix(0, ts))
	return age >= -5*time.Second && age <= 10*time.Second
}

// UDP measures synthetic RTT and loss against a cooperating authenticated echo
// server. It is intentionally sequential, to avoid bursty network traffic.
func UDP(addr, token string, count int, timeout time.Duration) (UDPMetrics, error) {
	if err := validateUDPToken(token); err != nil {
		return UDPMetrics{}, err
	}
	if count < 1 || count > 100 || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return UDPMetrics{}, errors.New("count must be 1-100 and timeout 100ms-30s")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return UDPMetrics{}, fmt.Errorf("invalid UDP host:port: %w", err)
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return UDPMetrics{}, err
	}
	defer conn.Close()
	samples := make([]float64, 0, count)
	buf := make([]byte, udpPacketSize)
	for i := 0; i < count; i++ {
		pkt, err := udpPacket(token)
		if err != nil {
			return UDPMetrics{}, err
		}
		start := time.Now()
		if err := conn.SetDeadline(start.Add(timeout)); err != nil {
			return UDPMetrics{}, err
		}
		if _, err := conn.Write(pkt); err != nil {
			continue
		}
		n, err := conn.Read(buf)
		if err == nil && n == udpPacketSize && hmac.Equal(buf[:n], pkt) {
			samples = append(samples, float64(time.Since(start).Microseconds())/1000)
		}
	}
	summary := Summarize(addr, count, samples)
	summary.Transport = "authenticated UDP echo"
	summary.Note = "Synthetic UDP echo between consenting peers, NOT game-server ping or a VPN. Loss includes unanswered/time-out requests."
	jitter := 0.0
	if len(samples) > 1 {
		for i := 1; i < len(samples); i++ {
			jitter += math.Abs(samples[i] - samples[i-1])
		}
		jitter /= float64(len(samples) - 1)
	}
	return UDPMetrics{TCPResult: summary, JitterMS: jitter}, nil
}

type rateBucket struct {
	window time.Time
	count  int
}

// ServeUDP runs an opt-in echo responder on a caller-owned socket. The CLI
// binds to localhost by default, and exposing it requires an explicit address.
// Invalid, unauthenticated or oversized requests never receive a reply.
func ServeUDP(ctx context.Context, conn net.PacketConn, token string) error {
	if err := validateUDPToken(token); err != nil {
		return err
	}
	defer conn.Close()
	buckets := make(map[string]rateBucket)
	buf := make([]byte, 128)
	expiry := time.Now().Add(time.Minute)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return err
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		now := time.Now()
		if !validUDPPacket(buf[:n], token, now) {
			continue
		}
		// Cap at 25 authenticated echoes/second per source IP.
		host, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			continue
		}
		b := buckets[host]
		if now.Sub(b.window) >= time.Second {
			b = rateBucket{window: now}
		}
		if b.count >= 25 {
			continue
		}
		b.count++
		buckets[host] = b
		if now.After(expiry) {
			for ip, entry := range buckets {
				if now.Sub(entry.window) > time.Minute {
					delete(buckets, ip)
				}
			}
			expiry = now.Add(time.Minute)
		}
		// Identical-size echo prevents reflection amplification by payload size.
		_, _ = conn.WriteTo(buf[:n], addr)
	}
}
