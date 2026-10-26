# Roadmap / Task board

Roadmap items are **planned, not delivered**. Track each implementation as a GitHub issue.

## Phase 0 — foundation (included in this starter)

- [x] Project governance, contribution and security documentation
- [x] TCP-connect diagnostic with summary stats
- [x] Demonstration route-policy engine with suffix-boundary matching
- [x] Illustrative peer-ranking heuristic with tests
- [x] Basic CI configuration

## Phase 1 — measurement and security design

- [ ] **good first issue**: Kotlin Android app shell with English/Persian i18n (no VPN mode yet)
- [ ] **good first issue**: Windows desktop client shell and profile switcher
- [ ] Define threat model and attacker capabilities (network censor, malicious exits, impostor peers)
- [ ] Research and prototype non-amplifying authenticated UDP RTT measurement on consenting peers
- [ ] Add true UDP RTT/jitter/loss measurement with protocol versioning and abuse controls
- [ ] Produce repeatable per-ISP, per-game benchmark datasets; redact IPs
- [ ] Build metrics visualizer; avoid deceptive TCP/game ping comparisons

## Phase 2 — opt-in private network proof of concept

- [ ] Specify cryptographic peer enrollment and authentication; externally review protocol
- [ ] Reuse audited WireGuard components; avoid novel crypto
- [ ] Build a **private, invitation-only** consent-based exit node proof of concept with egress restrictions
- [ ] Add per-process and per-domain policy that enforces DNS and IPv6 correctness
- [ ] Gate public relay launch behind security review, quotas, rate limiting and operator safety controls

## Phase 3 — Gaming (UDP)

- [ ] End-to-end game UDP compatibility and NAT traversal where feasible
- [ ] Direct-vs-relay routing with latency thresholds and seamless recovery
- [ ] Detect adverse routes, packet loss, MTU blackholes; fail safe
- [ ] Tests with opt-in multiplayer scenarios; report median/p95 RTT, loss and jitter

## Phase 4 — Smart Access and Developer profiles

- [ ] Domain/process targeting, accessible DNS and split tunneling
- [ ] Document limits of geo-IP routing versus account/identity restrictions
- [ ] Desktop/Android installers, signed release pipeline and update mechanism

## Phase 5 — optional decentralization enhancements

- [ ] Verifiable signed peer catalogs with multiple independent distribution paths
- [ ] Peer reputation and anti-Sybil system without collecting browsing histories
- [ ] Evaluate whether a blockchain adds value to governance; **never put user traffic on-chain**

## Priorities

Security, honest performance claims, network availability, and operator consent are release blockers, not stretch goals.
