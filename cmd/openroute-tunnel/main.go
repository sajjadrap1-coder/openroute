// OpenRoute opt-in tunnel prototype: an authenticated TCP relay and local
// HTTP CONNECT client. Not a WireGuard VPN or UDP game accelerator.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/sajjadrap1-coder/openroute/internal/tunnel"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "init":
		f := flag.NewFlagSet("init", flag.ContinueOnError)
		dir := f.String("dir", "identities", "output directory for PRIVATE identities")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		p, err := tunnel.GeneratePKI(*dir)
		if err != nil {
			return err
		}
		fmt.Printf("Generated test identities in %s. NEVER upload client.key or relay.key to GitHub.\n", *dir)
		fmt.Printf("Relay operator uses %s, %s and %s. Client uses %s, %s and %s.\n", p.CA, p.ServerCert, p.ServerKey, p.CA, p.ClientCert, p.ClientKey)
		return nil
	case "relay":
		f := flag.NewFlagSet("relay", flag.ContinueOnError)
		bind := f.String("listen", "127.0.0.1:9443", "relay bind address; public bind is a conscious opt-in")
		allow := f.String("allow", "", "comma-separated exact approved destinations, e.g. example.org:443")
		identities := f.String("identities", "identities", "directory containing relay identity and CA")
		local := f.Bool("allow-local-targets", false, "loopback test only; forbidden for public bind")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		approved, err := tunnel.ParseAllowTargets(*allow)
		if err != nil {
			return err
		}
		cfg, err := tunnel.ServerTLS(*identities)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", *bind)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "OpenRoute TLS relay listening on %s; approved targets: %d; anonymous access disabled\n", ln.Addr(), len(approved))
		return (&tunnel.Relay{TLS: cfg, Allow: approved, AllowLocalTargets: *local}).Serve(signalContext(), ln)
	case "proxy":
		f := flag.NewFlagSet("proxy", flag.ContinueOnError)
		bind := f.String("listen", "127.0.0.1:8787", "local HTTP CONNECT proxy address")
		relay := f.String("relay", "127.0.0.1:9443", "trusted relay host:port")
		identities := f.String("identities", "identities", "directory with client identity and relay CA")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		if err := tunnel.ValidateLoopbackBind(*bind); err != nil {
			return err
		}
		cfg, err := tunnel.ClientTLS(*identities)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", *bind)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "OpenRoute HTTP CONNECT proxy on %s -> TLS relay %s (no UDP support)\n", ln.Addr(), *relay)
		return (&tunnel.Proxy{RelayAddress: *relay, TLS: cfg}).Serve(signalContext(), ln)
	case "version":
		fmt.Println("OpenRoute tunnel v0.2.0-alpha")
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func signalContext() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx
}
func usage() {
	fmt.Print(`OpenRoute 0.2.0-alpha: mutually authenticated TLS 1.3 TCP relay
Commands:
  openroute-tunnel init --dir identities
  openroute-tunnel relay --listen 127.0.0.1:9443 --allow example.org:443 --identities identities
  openroute-tunnel proxy --listen 127.0.0.1:8787 --relay 127.0.0.1:9443 --identities identities
  openroute-tunnel version

Connect applications using HTTP proxy http://127.0.0.1:8787.
Relay only permits exact approved hosts, and blocks private/special IPs by default.
This is NOT a UDP tunnel / full device VPN / automatic sanction bypass.
`)
}
