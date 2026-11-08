# Contributing to Pinga53

Thanks for helping build the jungle.

1. **Sign the CLA.** Every pull request needs the line from [CLA.md](CLA.md)
   in its description, and signed-off commits (`git commit -s`).
2. **Open an issue first** for anything bigger than a small fix.
3. **Tests.** From `engine/`: `go test -race ./...` must pass, and
   `gofmt -l .` must print nothing.
4. **New feed sources** need the provider's terms, quoted and dated, for
   every operation in the source registry. If the terms are unclear, the
   grant is `unknown` and the source stays disabled. We don't guess.
5. **No household data** in issues, tests or fixtures: no real client IPs,
   hostnames, query logs or allow lists.
6. **No secrets.** Never commit keys, passwords or tokens.

Security problems: see [SECURITY.md](SECURITY.md), not public issues.
