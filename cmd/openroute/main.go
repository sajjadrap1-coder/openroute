// OpenRoute is an experimental diagnostics and route-policy CLI.
// It is NOT a VPN or a production censorship-circumvention tunnel.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sajjadrap1-coder/openroute/internal/policy"
	"github.com/sajjadrap1-coder/openroute/internal/probe"
	"github.com/sajjadrap1-coder/openroute/internal/score"
)

const version = "0.1.1-dev"

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
	case "version":
		fmt.Println("openroute", version)
		return nil
	case "probe":
		fs := flag.NewFlagSet("probe", flag.ContinueOnError)
		host := fs.String("host", "", "target hostname or IP (no URL scheme)")
		port := fs.Int("port", 443, "TCP target port")
		count := fs.Int("count", 5, "number of TCP connect attempts")
		timeout := fs.Duration("timeout", 1500*time.Millisecond, "timeout for each connect")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		if *host == "" {
			return errors.New("--host is required")
		}
		result, err := probe.TCP(*host, *port, *count, *timeout)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "udp-probe":
		fs := flag.NewFlagSet("udp-probe", flag.ContinueOnError)
		addr := fs.String("addr", "127.0.0.1:29381", "consenting OpenRoute echo peer host:port")
		count := fs.Int("count", 5, "number of authenticated UDP echoes")
		timeout := fs.Duration("timeout", time.Second, "timeout for each echo")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		result, err := probe.UDP(*addr, os.Getenv("OPENROUTE_UDP_TOKEN"), *count, *timeout)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "udp-listen":
		fs := flag.NewFlagSet("udp-listen", flag.ContinueOnError)
		bind := fs.String("bind", "127.0.0.1:29381", "listen address, loopback only by default")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		conn, err := net.ListenPacket("udp", *bind)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "OpenRoute authenticated UDP diagnostics listener:", conn.LocalAddr())
		return probe.ServeUDP(context.Background(), conn, os.Getenv("OPENROUTE_UDP_TOKEN"))
	case "route":
		fs := flag.NewFlagSet("route", flag.ContinueOnError)
		host := fs.String("host", "", "destination hostname")
		mode := fs.String("mode", "smart", "smart, gaming, ai, or direct")
		config := fs.String("config", "config.example.json", "policy JSON file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		cfg, err := policy.ReadFile(*config)
		if err != nil {
			return err
		}
		decision, err := cfg.Decide(strings.TrimSpace(*host), *mode)
		if err != nil {
			return err
		}
		return printJSON(decision)
	case "rank":
		fs := flag.NewFlagSet("rank", flag.ContinueOnError)
		config := fs.String("input", "peers.example.json", "peer metrics JSON file")
		mode := fs.String("mode", "gaming", "gaming, smart, or ai")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		peerList, err := score.ReadFile(*config)
		if err != nil {
			return err
		}
		ranked, err := score.Rank(peerList, *mode)
		if err != nil {
			return err
		}
		return printJSON(ranked)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (try openroute help)", args[0])
	}
}

func printJSON(value any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(value)
}

func usage() {
	fmt.Println(`OpenRoute v0.1.1-dev — network research toolkit (not yet a VPN)

Usage:
  openroute version
  openroute probe --host example.org --port 443 --count 5
  openroute udp-listen --bind 127.0.0.1:29381
  openroute udp-probe --addr 127.0.0.1:29381 --count 5
  openroute route --mode gaming --host steamcommunity.com --config config.example.json
  openroute rank --mode gaming --input peers.example.json

TCP probe metrics are connection setup times. Authenticated UDP metrics are synthetic peer RTT, not actual game ping.
For UDP diagnostics set OPENROUTE_UDP_TOKEN to the same random 16+-byte secret on consenting peers.
See README.md and docs/architecture.md before deploying any exit nodes.`)
}
