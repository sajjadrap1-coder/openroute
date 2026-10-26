package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Proxy provides local HTTP CONNECT -> mutually authenticated TLS relay.
// Only bind it to loopback; HTTP proxy credentials are not implemented.
type Proxy struct {
	RelayAddress string
	TLS          *tls.Config
}

func (p *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	if p.TLS == nil || p.TLS.MinVersion < tls.VersionTLS13 || p.TLS.ServerName == "" {
		return errors.New("client requires verified TLS 1.3 configuration")
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() {
		return errors.New("local proxy must listen on loopback only")
	}
	srv := &http.Server{Handler: http.HandlerFunc(p.handle), ReadHeaderTimeout: 8 * time.Second, MaxHeaderBytes: 8192, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	err := srv.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" {
		http.Error(w, "HTTP CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	target := strings.ToLower(r.Host)
	if _, _, err := validateTarget(target); err != nil {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	// Bound initial negotiation so stalled or unreachable relays do not hang UI.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp", p.RelayAddress, p.TLS)
	if err != nil {
		http.Error(w, "relay unavailable", http.StatusBadGateway)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := binary.Write(conn, binary.BigEndian, uint16(len(target))); err != nil {
		http.Error(w, "relay write error", http.StatusBadGateway)
		return
	}
	if _, err := io.WriteString(conn, target); err != nil {
		http.Error(w, "relay write error", http.StatusBadGateway)
		return
	}
	answer := []byte{0}
	if _, err := io.ReadFull(conn, answer); err != nil || answer[0] != 1 {
		http.Error(w, "destination not approved or unreachable", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP hijacking unavailable", http.StatusInternalServerError)
		return
	}
	client, b, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	_ = conn.SetDeadline(time.Time{})
	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	// b.Reader contains bytes already buffered by the HTTP parser.
	go func() { _, _ = io.Copy(conn, b.Reader); _ = conn.CloseWrite(); done <- struct{}{} }()
	go func() {
		_, _ = io.Copy(client, conn)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// ProxyURL returns the loopback address suitable for application proxy settings.
func ProxyURL(port int) string { return "http://127.0.0.1:" + strconv.Itoa(port) }
func ValidateLoopbackBind(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("proxy listener must use loopback IP (e.g. 127.0.0.1), got %q", host)
	}
	return nil
}
