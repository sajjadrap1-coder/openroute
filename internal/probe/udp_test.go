package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

const testUDPToken = "32-characters-demo-secret-for-tests!"

func TestUDPLoopback(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeUDP(ctx, conn, testUDPToken) }()
	result, err := UDP(conn.LocalAddr().String(), testUDPToken, 4, 250*time.Millisecond)
	if err != nil || result.Successes != 4 || result.Transport != "authenticated UDP echo" {
		t.Fatalf("unexpected UDP result: %+v err=%v", result, err)
	}
	result, err = UDP(conn.LocalAddr().String(), "different-token-32-characters-long!", 1, 150*time.Millisecond)
	if err != nil || result.Successes != 0 || result.Failures != 1 {
		t.Fatalf("unauthorized request should not be echoed: %+v err=%v", result, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestUDPTokenAndPacketAuthentication(t *testing.T) {
	if err := validateUDPToken("short"); err == nil {
		t.Fatal("short token accepted")
	}
	pkt, err := udpPacket(testUDPToken)
	if err != nil {
		t.Fatal(err)
	}
	if !validUDPPacket(pkt, testUDPToken, time.Now()) {
		t.Fatal("valid packet refused")
	}
	pkt[10] ^= 1
	if validUDPPacket(pkt, testUDPToken, time.Now()) {
		t.Fatal("modified packet accepted")
	}
}
