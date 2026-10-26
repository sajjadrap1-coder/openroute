package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Relay connects an authenticated client to one of its operator-approved
// targets. This is an opt-in TCP relay, not a public exit proxy or a VPN.
type Relay struct {
	TLS               *tls.Config
	Allow             map[string]bool
	AllowLocalTargets bool // loopback demo only; never enable for a public listener
	MaxSessions       int
}

func ParseAllowTargets(csv string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, raw := range strings.Split(csv, ",") {
		target := strings.ToLower(strings.TrimSpace(raw))
		if target == "" {
			continue
		}
		if _, _, err := validateTarget(target); err != nil {
			return nil, fmt.Errorf("invalid allow target %q: %w", target, err)
		}
		out[target] = true
	}
	if len(out) == 0 {
		return nil, errors.New("specify at least one exact target with --allow host:port")
	}
	return out, nil
}
func validateTarget(target string) (string, int, error) {
	if target == "" || len(target) > 255 || strings.ContainsAny(target, "/\\@ \t\r\n") {
		return "", 0, errors.New("invalid address")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	if host == "" {
		return "", 0, errors.New("empty host")
	}
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return "", 0, errors.New("hostname too long")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", 0, errors.New("invalid hostname label")
			}
			for _, ch := range label {
				if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
					return "", 0, errors.New("invalid hostname character")
				}
			}
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid port")
	}
	return host, port, nil
}
func isPublic(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	if addr.Is4() {
		for _, prefix := range []string{"100.64.0.0/10", "0.0.0.0/8", "192.0.0.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
			p := netip.MustParsePrefix(prefix)
			if p.Contains(addr) {
				return false
			}
		}
	}
	return true
}
func (r *Relay) targetConn(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := validateTarget(target)
	if err != nil {
		return nil, err
	}
	if !r.Allow[strings.ToLower(target)] {
		return nil, errors.New("target not explicitly approved by relay operator")
	}
	resolver := net.DefaultResolver
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !r.AllowLocalTargets && !isPublic(ip.IP) {
			continue
		}
		if r.AllowLocalTargets && !net.ParseIP(ip.IP.String()).IsLoopback() {
			continue
		}
		conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.IP.String(), strconv.Itoa(port)))
		if e == nil {
			return conn, nil
		}
		err = e
	}
	if err == nil {
		err = errors.New("no permitted destination IP addresses (private/special ranges blocked)")
	}
	return nil, err
}
func (r *Relay) Serve(ctx context.Context, listener net.Listener) error {
	if r.TLS == nil || r.TLS.MinVersion < tls.VersionTLS13 || r.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		return errors.New("relay requires mutual TLS 1.3")
	}
	if len(r.Allow) == 0 {
		return errors.New("empty allowlist")
	}
	if r.AllowLocalTargets {
		addr, ok := listener.Addr().(*net.TCPAddr)
		if !ok || !addr.IP.IsLoopback() {
			return errors.New("--allow-local-targets is only permitted with a loopback listener")
		}
	}
	max := r.MaxSessions
	if max <= 0 || max > 256 {
		max = 32
	}
	sem := make(chan struct{}, max)
	var wg sync.WaitGroup
	go func() { <-ctx.Done(); _ = listener.Close() }()
	defer func() { _ = listener.Close(); wg.Wait() }()
	for {
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-sem }(); r.handle(ctx, raw) }()
		default:
			_ = raw.Close()
		}
	}
}
func (r *Relay) handle(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	conn := tls.Server(raw, r.TLS)
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		return
	}
	var size uint16
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return
	}
	if size == 0 || size > 255 {
		return
	}
	dest := make([]byte, size)
	if _, err := io.ReadFull(conn, dest); err != nil {
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	target, err := r.targetConn(dialCtx, string(dest))
	if err != nil {
		_, _ = conn.Write([]byte{0})
		return
	}
	defer target.Close()
	if _, err = conn.Write([]byte{1}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	bridge(target, conn)
}

// bridge preserves half-closes rather than terminating the opposite direction
// immediately: important for protocols that send a response after request EOF.
func bridge(tcp net.Conn, encrypted *tls.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(tcp, encrypted)
		if cw, ok := tcp.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() { _, _ = io.Copy(encrypted, tcp); _ = encrypted.CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
}
