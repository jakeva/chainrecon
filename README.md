# chainrecon

**Predict the next supply chain attack.**

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/chainrecon/chainrecon/actions/workflows/ci.yml/badge.svg)](https://github.com/chainrecon/chainrecon/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/chainrecon/chainrecon)](https://github.com/chainrecon/chainrecon/releases/latest)
[![Homebrew](https://img.shields.io/badge/Homebrew-chainrecon%2Ftap-FBB040?logo=homebrew)](https://github.com/chainrecon/homebrew-tap)

chainrecon profiles npm packages from the attacker's perspective, surfacing the signals that make a package an attractive target for compromise before an attack happens.

## Quick start

```
$ brew install chainrecon/tap/chainrecon
$ chainrecon scan axios

 Package: axios
 Version: 1.14.0
 Weekly Downloads: 99,988,070

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
  [HIGH] Provenance is intermittent across versions
  [MEDIUM] Mixed publishing methods detected
  [CRITICAL] Single maintainer with full publish access
  [HIGH] All maintainers using personal email addresses
  [MEDIUM] Unscoped package with limited maintainer access
  [CRITICAL] Extremely high blast radius
  [CRITICAL] Maintainer email changed between versions
  [HIGH] Unknown publisher on recent version
  [LOW] Multiple different publishers across recent versions
  [MEDIUM] OpenSSF Scorecard: 5.5/10
  [HIGH] Scorecard Token-Permissions: 0/10
  [HIGH] Scorecard Pinned-Dependencies: 1/10
```

## Signals

| Signal | Weight | Description |
|---|---|---|
| `Provenance Consistency` | 25.5% | Tracks npm provenance attestations across versions. Detects drops and gaps. |
| `Publishing Hygiene` | 21.25% | Classifies publish method: CI/CD, direct token, mixed, or legacy. |
| `Maintainer Concentration` | 21.25% | Bus factor, single publisher detection, personal vs org email. |
| `Identity Stability` | 17% | Email changes, new publishers on established packages, cadence anomalies. |
| `OpenSSF Scorecard` | 15% | Imported from [scorecard.dev](https://scorecard.dev), inverted (higher = more vulnerable). |
| `Blast Radius` | multiplier | Weekly downloads, dependent count, security tooling multiplier. |
| `Tag Correlation` | finding | Flags npm versions with no matching GitHub release or tag. |

> Weights shown are with Scorecard enabled. Without Scorecard, the four core signals rebalance to 30/25/25/20.

## Scoring

```
target_score = attack_surface × blast_radius
```

Attack surface is a weighted average of the signals above (0 to 10). Blast radius scales it. Target score ranges 0 to 100.

| | Score |
|---|---|
| ![LOW](https://img.shields.io/badge/LOW-3CB371) | Below 25 |
| ![MEDIUM](https://img.shields.io/badge/MEDIUM-F0AD4E) | 25 to 49 |
| ![HIGH](https://img.shields.io/badge/HIGH-E87D2F) | 50 to 69 |
| ![CRITICAL](https://img.shields.io/badge/CRITICAL-D9534F) | 70+ |

The score indicates how attractive a package is as a target, not whether it is compromised.

## CLI reference

| Command | Description |
|---|---|
| `chainrecon scan <package>` | Scan an npm package |
| `chainrecon version` | Print version info |

| Flag | Default | Description |
|---|---|---|
| `--format` | `table` | Output format (`table` or `json`) |
| `--depth` | `20` | Number of versions to check for provenance history |
| `--timeout` | `2m` | Request timeout |
| `--no-cache` | `false` | Bypass local cache |
| `--no-scorecard` | `false` | Skip OpenSSF Scorecard lookup |
| `--no-github` | `false` | Skip GitHub release/tag lookup |
| `--github-token` | | GitHub API token for higher rate limits |

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
