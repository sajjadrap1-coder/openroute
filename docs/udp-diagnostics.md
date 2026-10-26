# Authenticated UDP diagnostics (experimental)

This is a synthetic RTT/packet-loss check between **two consenting OpenRoute peers**. It does not proxy traffic, emulate a multiplayer game, or measure a game's own server ping.

## Local test

Go 1.23+ is required. Open two terminals in the repository. Set the same strong, randomly generated pre-shared value in both terminals using an environment variable (do not put tokens in command line arguments or commit them).

On Linux/macOS:

```sh
export OPENROUTE_UDP_TOKEN="$(openssl rand -hex 32)"
go run ./cmd/openroute udp-listen --bind 127.0.0.1:29381
```

Copy the same token securely to your second terminal (do not generate another one), then:

```sh
go run ./cmd/openroute udp-probe --addr 127.0.0.1:29381 --count 5
```

On PowerShell, set `$env:OPENROUTE_UDP_TOKEN` to the same randomly generated secret in both terminals and run the corresponding `go run` commands.

## Consent and safety

- The listener binds only to `127.0.0.1` by default. External binding requires an explicit `--bind` value and should be limited to **trusted, explicitly consenting hosts** with a firewall.
- The protocol sends authenticated fixed-size 64-byte datagrams using HMAC-SHA256 and replies with the identical datagram. Invalid requests receive no response.
- There is a basic 25 replies/second per-source-IP limit, which is **not** a full anti-abuse or DDoS defense.
- Use a new high-entropy token for each session. Keep it out of public screenshots, logs, issues and pull requests.
- Client output reports response success, median/p95 RTT, a mean absolute successive RTT difference ("jitter") and timeouts as unanswered probes.
- Measurements do not confirm end-to-end encryption, user anonymity, VPN functionality or ISP accessibility.
- A public Internet-facing test service is not supported or security-audited. Do not expose this sample broadly.

## Development validation

```sh
go test -race ./...
go vet ./...
```

Track hardening and protocol review in the issue backlog, especially token rotation, explicit packet replay detection, timestamp validation, rate limits and independent security review.
