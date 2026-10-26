# OpenRoute Tunnel v0.2.0-alpha — private TCP relay quickstart

This experimental build carries real TCP streams via an **HTTP CONNECT proxy bound to 127.0.0.1**, over a mutually authenticated **TLS 1.3** connection to a **consenting volunteer exit node**. It is NOT a full-device VPN, UDP tunnel, game accelerator, automatically decentralized network, or an identity/sanctions bypass guarantee. Only explicitly approved destinations work.

## Preparation

1. Build with Go 1.23+: `go build -o openroute-tunnel ./cmd/openroute-tunnel` or use the prebuilt Windows/Linux executable.
2. On a trusted offline/private machine run `openroute-tunnel init --dir identities` exactly once to generate `ca.crt`, `relay.crt`, `relay.key`, `client.crt`, and `client.key`.
3. Securely deliver `ca.crt`, `relay.crt`, `relay.key` to the **relay operator**; deliver `ca.crt`, `client.crt`, `client.key` to the **client**. Never commit keys. The CA signing key is deliberately discarded after this single invitation; rotating the identity set requires regenerating and distributing credentials.

## Relay host (consenting owner only)

Local demo:

```bash
./openroute-tunnel relay --listen 127.0.0.1:9443 --allow example.org:443 --identities identities
```

When explicitly exposing a relay outside its host, use `--listen 0.0.0.0:9443` only with firewall rules restricting which client networks can reach it. Select exact allowed `host:port` combinations, e.g. `--allow example.org:443,github.com:443`. The relay rejects private/special destinations by default. There is no anonymous access and no wildcard target support. Never publish a relay's private key.

## Client

```bash
./openroute-tunnel proxy --listen 127.0.0.1:8787 --relay RELAY_HOST:9443 --identities identities
curl --noproxy '' -x http://127.0.0.1:8787 https://example.org/
```

Use the local HTTP proxy address in an application that supports HTTP CONNECT. No system-wide IP/TUN routing is installed. Proxy only binds to loopback and has **no local password**; other software on the same machine may use any destination approved by the exit operator. Do not run the proxy on a shared or untrusted computer.

## Important limitations

- This release is TCP-only; it does not deliver UDP game packets or unchanged gaming ping. No Android UI, automatic peer discovery, censorship-resistant bootstrap, multiplexing or dynamic app routing.
- The exit operator can observe destination addresses and connection metadata; application HTTPS is encrypted end-to-end with the destination separately from tunnel TLS.
- DNS resolution of target names occurs at the exit. Local apps may still perform their own DNS queries; no DNS leak protection is provided.
- Mutual TLS ensures both endpoints have the expected private identities, not that those endpoints are trustworthy. Identities are not per-user-revocable. Rotate compromised keys and rebuild the set.
- Only explicitly allowlisted destinations work; auth/account/billing restrictions are outside this tool's scope.
- Designed for private technical tests, not for sensitive or production deployment. An independent security review is still required.

## Developer validation

```bash
go test -race ./...
go vet ./...
```

Integration tests use loopback TCP sockets, a synthetic echo target, an ephemeral ECDSA test CA, mutual TLS, and the local HTTP CONNECT proxy. Do not use the test-only `--allow-local-targets` flag on an Internet-facing service; the relay forbids that combination.
