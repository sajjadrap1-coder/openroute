# OpenRoute

**Open-source research project for adaptive, decentralized network access — Windows & Android.**

> **Status: v0.1.1-dev, foundational CLI only. NOT a functional VPN, circumvention app, game accelerator, or security-reviewed tunnel.**

We are designing one client with three selectable profiles:

1. **Gaming:** prefer low RTT, jitter, loss and stable UDP paths. Routing can improve some poor routes but cannot guarantee unchanged or lower ping.
2. **Smart Access:** per-domain/application split-tunnel policy; direct connections whenever appropriate, opt-in volunteer egress for selected destinations.
3. **AI & Developer:** reliable access to developer tools and AI endpoints where legally and contractually permitted. It does not bypass account, identity, billing, or other non-IP restrictions.

## Why not store traffic on a blockchain?

A blockchain cannot carry game packets at competitive latency. Any ledger, if used at all, would be optional for audit/registry metadata. The dataplane should run off-chain, preferably using audited implementations of WireGuard (for UDP) and/or QUIC/MASQUE with careful testing. No cryptocurrency or token is required.

## Try the current prototype

Requires Go 1.23+ for building, no external Go dependencies. In this folder:

```bash
go test ./...
go run ./cmd/openroute version
go run ./cmd/openroute probe --host example.org --port 443 --count 5
go run ./cmd/openroute route --mode gaming --host steamcommunity.com
go run ./cmd/openroute rank --mode gaming
```

For experimental consent-based UDP echo RTT/jitter checks, see [UDP diagnostics](docs/udp-diagnostics.md). They are **not** real game-server ping or a VPN.

**What these commands do:** measure TCP connection setup, simulate routing-policy decisions, and rank manually provided peer metrics. They do not proxy actual traffic. TCP-connect time is not game ping. The included example peers are fictional.

## Goals & principles

- Decentralized bootstrap and volunteer exit relays; **no paid central VPS required** for the intended design, but accessible exit machines *are* required.
- Android (VPNService) and Windows (Wintun/approved tunnel integration) as *future* clients.
- Reliable UDP for multiplayer, without forcing extra hops when direct routes are better.
- Strong transport encryption, exit operator consent, abuse safeguards, no default user activity logging, authenticated discovery, clear trust model.
- Benchmarks against direct access; publish median/p95 RTT, jitter, loss, and goodput. Honest failures, no zero-overhead promises.

## Project map

- [`ROADMAP.md`](ROADMAP.md): phases and starter tasks.
- [`docs/architecture.md`](docs/architecture.md): component plan and trust boundaries.
- [`docs/benchmarks.md`](docs/benchmarks.md): how to evaluate claims.
- [`README.fa.md`](README.fa.md): Persian quickstart.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): contribution workflow.
- [`SECURITY.md`](SECURITY.md): security disclosures and non-goals.

## Looking for contributors

Contributions welcome in Go, Android/Kotlin, Windows, transport protocols, distributed systems, application security, usability, testing and documentation. Check the Roadmap and file an issue before writing a large feature. An implementation of a VPN or relay is **not yet included**.

## License

MIT, see [`LICENSE`](LICENSE). This is an experimental project and has not undergone a security audit.