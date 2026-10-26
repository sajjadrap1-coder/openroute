# Contributing to OpenRoute

Welcome! Please open an issue before implementing a large feature. This is a multilingual open-source project; English and Persian are welcome.

1. Read [`ROADMAP.md`](ROADMAP.md) and [`docs/architecture.md`](docs/architecture.md).
2. For bug reports, include your OS, Go version, minimal reproduction and *redacted* diagnostics. Never post tokens, keys, private IPs, real accounts or game credentials.
3. Fork the repository, create a focused branch, add tests, run `go test ./...` and submit a pull request explaining scope and measured impact.
4. Security-sensitive tunnel/crypto code requires a threat model, review and tests. Avoid custom cryptography.
5. Volunteer egress code must default to disabled and require explicit owner consent with abuse prevention.
6. Be respectful and keep performance claims reproducible.

Starter tasks: Android UI shell, Windows UI shell, i18n, metric test fixtures, benchmark plotting, documentation, security review.
