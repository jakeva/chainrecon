# chainrecon

**Predict the next supply chain attack.**

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/chainrecon/chainrecon/actions/workflows/ci.yml/badge.svg)](https://github.com/chainrecon/chainrecon/actions/workflows/ci.yml)

chainrecon profiles npm packages from the attacker's perspective, surfacing the signals that make a package an attractive target for compromise before an attack happens.

```bash
brew install chainrecon/tap/chainrecon
# or
go install github.com/chainrecon/chainrecon/cmd/chainrecon@latest

chainrecon scan axios
```

```
 Package: axios
 Version: 1.14.0
 Weekly Downloads: 101,121,575

 ┌─────────────────────────┬───────────┬─────────────────────────────────────────────┐
 │ Signal                  │ Score     │ Detail                                      │
 ├─────────────────────────┼───────────┼─────────────────────────────────────────────┤
 │ Provenance              │ 7.5/10    │ Provenance is intermittent across versions  │
 │ Publishing Hygiene      │ 5.0/10    │ Mixed publishing methods detected           │
 │ Maintainer Risk         │ 9.0/10    │ Single maintainer with full publish access  │
 │ Identity Stability      │ 8.0/10    │ Maintainer email changed between versions   │
 │ Scorecard (imported)    │ 4.5/10    │ OpenSSF Scorecard: 5.5/10                   │
 │ Blast Radius            │ 10.0/10   │ Extremely high blast radius                 │
 ├─────────────────────────┼───────────┼─────────────────────────────────────────────┤
 │ Attack Surface          │ 6.9/10    │                                             │
 │ Target Score            │ 69.0      │ HIGH                                        │
 └─────────────────────────┴───────────┴─────────────────────────────────────────────┘

 Key Findings:
  [CRITICAL] Single maintainer with full publish access
  [CRITICAL] Maintainer email changed between versions
  [HIGH] Provenance is intermittent across versions
  [HIGH] All maintainers using personal email addresses
  [MEDIUM] OpenSSF Scorecard: 5.5/10
  [HIGH] Scorecard Token-Permissions: 0/10
  [HIGH] Scorecard Pinned-Dependencies: 1/10
```

## Signals

| Signal | Description |
|---|---|
| Provenance Consistency | Tracks npm provenance attestations across versions. Detects drops and gaps. |
| Publishing Hygiene | Classifies publish method: CI/CD, direct token, mixed, or legacy. |
| Maintainer Concentration | Bus factor, single publisher detection, personal vs org email. |
| Blast Radius | Weekly downloads, dependent count, security tooling multiplier. |
| Identity Stability | Email changes, new publishers on established packages, cadence anomalies. |
| OpenSSF Scorecard | Imported from scorecard.dev, inverted to match convention (higher = more vulnerable). Weighted 15%. |

Tag correlation compares npm versions against GitHub releases and tags, flagging versions with no matching tag.

## Scoring

```
target_score = attack_surface × blast_radius
```

Each signal produces a 0 to 10 score. Attack surface is a weighted average. Target score ranges 0 to 100.

| Rating | Score |
|---|---|
| LOW | Below 25 |
| MEDIUM | 25 to 49 |
| HIGH | 50 to 69 |
| CRITICAL | 70+ |

The score indicates how attractive a package is as a target, not whether it is compromised.

## Usage

```bash
chainrecon scan axios              # scan a package
chainrecon scan axios --format json # JSON output
chainrecon scan axios --depth 50   # check 50 versions for provenance history
chainrecon scan axios --timeout 5m # custom timeout (default 2m)
chainrecon scan axios --no-cache   # bypass local cache
chainrecon scan axios --no-scorecard # skip Scorecard lookup
chainrecon scan axios --no-github  # skip GitHub lookup
chainrecon scan axios --github-token ghp_xxx # higher rate limits
chainrecon version                 # print version
```

`GITHUB_TOKEN` env var is also supported.

## Build from source

```bash
git clone https://github.com/chainrecon/chainrecon.git
cd chainrecon
make build
./bin/chainrecon scan axios
```

## License

Apache 2.0. See [LICENSE](LICENSE).
