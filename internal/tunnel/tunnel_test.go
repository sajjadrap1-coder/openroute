package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startDemo(t *testing.T) (proxyAddr, target string, done func()) {
	t.Helper()
	dir := t.TempDir()
	if _, err := GeneratePKI(dir); err != nil {
		t.Fatal(err)
	}
	serverTLS, err := ServerTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := ClientTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			c, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	target = targetListener.Addr().String()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &Relay{TLS: serverTLS, Allow: map[string]bool{target: true}, AllowLocalTargets: true}
	relayDone := make(chan error, 1)
	go func() { relayDone <- relay.Serve(ctx, ln) }()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &Proxy{TLS: clientTLS, RelayAddress: ln.Addr().String()}
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- proxy.Serve(ctx, local) }()
	done = func() {
		cancel()
		_ = targetListener.Close()
		_ = local.Close()
		_ = ln.Close()
		select {
		case e := <-relayDone:
			if e != nil {
				t.Errorf("relay: %v", e)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay did not terminate")
		}
		select {
		case e := <-proxyDone:
			if e != nil {
				t.Errorf("proxy: %v", e)
			}
		case <-time.After(3 * time.Second):
			t.Error("proxy did not terminate")
		}
	}
	return local.Addr().String(), target, done
}
func connect(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(conn)
	status, err := rd.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, rd, status
}
func TestEndToEndAuthenticatedCONNECT(t *testing.T) {
	proxyAddr, target, done := startDemo(t)
	defer done()
	c, rd, status := connect(t, proxyAddr, target)
	defer c.Close()
	if !strings.Contains(status, "200 Connection Established") {
		t.Fatalf("unexpected status: %q", status)
	}
	if _, err := c.Write([]byte("hello relay")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("hello relay"))
	if _, err := io.ReadFull(rd, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello relay" {
		t.Errorf("incorrect echoed data: %q", b)
	}
}
func TestRejectUnapprovedDestination(t *testing.T) {
	proxyAddr, _, done := startDemo(t)
	defer done()
	c, _, status := connect(t, proxyAddr, "127.0.0.1:23456")
	defer c.Close()
	if !strings.Contains(status, "502 Bad Gateway") {
		t.Fatalf("unexpected status: %q", status)
	}
}
func TestCertCredentials(t *testing.T) {
	dir := t.TempDir()
	p, err := GeneratePKI(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GeneratePKI(dir); err == nil {
		t.Fatal("overwrote certificate")
	}
	for _, file := range []string{p.ServerKey, p.ClientKey} {
		st, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0077 != 0 {
			t.Fatalf("key permissions too permissive: %v", st.Mode())
		}
	}
	if _, err := ClientTLS(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := ServerTLS(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.crt"), []byte("junk"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientTLS(dir); err == nil {
		t.Fatal("corrupt certificate accepted")
	}
}
func TestTLSConfiguration(t *testing.T) {
	p, err := GeneratePKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client, err := ClientTLS(filepath.Dir(p.ClientCert))
	if err != nil {
		t.Fatal(err)
	}
	server, err := ServerTLS(filepath.Dir(p.ServerCert))
	if err != nil {
		t.Fatal(err)
	}
	if client.MinVersion != tls.VersionTLS13 || server.MinVersion != tls.VersionTLS13 || server.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("mutual TLS 1.3 not enforced")
	}
}
func TestAllowlistAndAddressRestrictions(t *testing.T) {
	if _, err := ParseAllowTargets(""); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	for _, target := range []string{"127.0.0.1:8080", "[::1]:8888", "example.org:443"} {
		if _, err := ParseAllowTargets(target); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"example.org", "*:443", "example.org:0", "example.org:70000", "example.org:443/evil"} {
		if _, err := ParseAllowTargets(target); err == nil {
			t.Errorf("accepted: %q", target)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.2", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "198.18.0.1"} {
		if isPublic(net.ParseIP(ip)) {
			t.Errorf("private IP %s accepted", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !isPublic(net.ParseIP(ip)) {
			t.Errorf("public IP %s refused", ip)
		}
	}
	if err := ValidateLoopbackBind("0.0.0.0:8787"); err == nil {
		t.Fatal("public local proxy accepted")
	}
	if err := ValidateLoopbackBind("127.0.0.1:8787"); err != nil {
		t.Fatal(err)
	}
}
func TestAllowLocalOnlyOnLoopback(t *testing.T) {
	serverTLS, err := ServerTLS(t.TempDir())
	if err == nil || serverTLS != nil {
		t.Fatal("expected failure without identities")
	}
	// Validate trust/safety gate even when TLS credentials are configured.
	dir := t.TempDir()
	if _, err = GeneratePKI(dir); err != nil {
		t.Fatal(err)
	}
	serverTLS, err = ServerTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip("cannot bind test address")
	}
	defer ln.Close()
	r := &Relay{TLS: serverTLS, Allow: map[string]bool{"127.0.0.1:1234": true}, AllowLocalTargets: true}
	if err := r.Serve(context.Background(), ln); err == nil {
		t.Fatal("local-targets allowed on public listener")
	}
}
