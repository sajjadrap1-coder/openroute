package probe

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestComparePathsAgainstLocalSOCKS(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() {
		for {
			c, e := proxy.Accept()
			if e != nil {
				return
			}
			go mockSocksConnect(c, t)
		}
	}()
	host, sport, _ := net.SplitHostPort(target.Addr().String())
	port := 0
	for _, ch := range sport {
		port = port*10 + int(ch-'0')
	}
	got, err := ComparePaths(host, port, proxy.Addr().String(), 3, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.Direct.Successes != 3 || got.SOCKS5.Successes != 3 || got.Direct.Attempts != 3 {
		t.Fatalf("%+v", got)
	}
}

func mockSocksConnect(c net.Conn, t *testing.T) {
	defer c.Close()
	greet := make([]byte, 3)
	if _, err := io.ReadFull(c, greet); err != nil {
		return
	}
	if greet[0] != 5 || greet[1] != 1 || greet[2] != 0 {
		t.Error("bad greeting")
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[3] != 1 {
		t.Error("expected IPv4 request")
		return
	}
	if _, err := io.CopyN(io.Discard, c, 6); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
}

func TestRejectExternalSOCKS(t *testing.T) {
	if _, err := ComparePaths("example.org", 443, "8.8.8.8:10808", 1, time.Second); err == nil {
		t.Fatal("expected external proxy rejection")
	}
	if _, err := ComparePaths("example.org", 443, "127.0.0.1:10808", 0, time.Second); err == nil {
		t.Fatal("expected count validation")
	}
}
