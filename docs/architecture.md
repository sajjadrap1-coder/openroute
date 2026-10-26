# Architecture design (proposal, not shipped)

```text
Windows app / Android VPNService
  |         \__ DNS and process/domain policy (split-tunnel)
  |                  |
  |          direct internet (default) --------> destination
  |
  +--> candidate selection + connectivity probes
              |
              +--> authenticated encrypted tunnel (future WireGuard / QUIC)
                               |
                       consenting volunteer exit node
                               |
                         destination internet
```

## Three profiles, one dataplane

- Gaming: prefer direct networking where best; UDP path selection, congestion/MTU diagnosis, fast fallback; no promise of unchanged ping.
- Smart: explicit routing rules and per-app control, with IPv6/DNS leak prevention in the final client.
- AI/Developer: prioritize reliable TCP/TLS and UDP/QUIC as supported; avoid implying that network routing resolves contractual or account restrictions.

## No specialized central server

No service can reach an arbitrary Internet destination merely by adding a blockchain: egress nodes with suitable connectivity are essential. Discovery may use local/imported signed peer catalogues, invitations and independently mirrored bootstrap metadata. **P2P does not imply that no machine acts as an egress server.**

## Trust model / required safeguards

1. Client authenticates both peer identity and session keys; prefer verified established transport implementations.
2. Exit node owners explicitly opt in, can turn it off, and define egress allowlists, quotas, abuse throttling and retention policies.
3. Exit operators can see destination addresses and timing; TLS protects HTTPS content but not all metadata. Client UI must explain this.
4. No anonymous open public exit on first release. No default traffic logging; no false promise of perfect anonymity.
5. Peer discovery must not blindly trust self-advertised speed, IP or identity. Prevent Sybil and malicious routing advertisements.
6. Handle relay failures, compromised nodes, DNS, IPv6, UDP, private-address/SSRF restrictions, network changes and software updates.
7. Avoid putting sensitive data on a blockchain. A decentralized control-plane alone cannot fix packet path economics.

## Technology candidates (subject to tests)

- Go for cross-platform network engine; reuse audited WireGuard components for UDP tunneling.
- Android Kotlin + VpnService (later); Windows GUI + supported networking interfaces (later).
- QUIC/MASQUE considered for compatible use cases; not a drop-in guarantee for games.

## Milestone acceptance

Before labeling any build 'working VPN': authenticated encrypted tunnel to a consenting egress, tested on real Windows and Android devices, DNS/IPv6 behavior verified, threat model reviewed, safe operator controls and measurable performance data.
