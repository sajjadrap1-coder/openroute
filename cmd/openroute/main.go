// OpenRoute is an experimental diagnostics and route-policy CLI.
// It is NOT a VPN or a production censorship-circumvention tunnel.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sajjadrap1-coder/openroute/internal/policy"
	"github.com/sajjadrap1-coder/openroute/internal/probe"
	"github.com/sajjadrap1-coder/openroute/internal/score"
)

const version = "0.1.0-dev"

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
	fmt.Println(`OpenRoute v0.1.0-dev — network research toolkit (not yet a VPN)

Usage:
  openroute version
  openroute probe --host example.org --port 443 --count 5
  openroute route --mode gaming --host steamcommunity.com --config config.example.json
  openroute rank --mode gaming --input peers.example.json

Metrics are TCP connection measurements, not ICMP ping or game UDP RTT.
See README.md and docs/architecture.md before deploying any exit nodes.`)
}
