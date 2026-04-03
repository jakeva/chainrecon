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

| Signal | Description |
|---|---|
| `Provenance Consistency` | Tracks npm provenance attestations across versions. Detects drops and gaps. |
| `Publishing Hygiene` | Classifies publish method: CI/CD, direct token, mixed, or legacy. |
| `Maintainer Concentration` | Bus factor, single publisher detection, personal vs org email. |
| `Identity Stability` | Email changes, new publishers on established packages, cadence anomalies. |
| `OpenSSF Scorecard` | Imported from [scorecard.dev](https://scorecard.dev), inverted (higher = more vulnerable). |
| `Blast Radius` | Weekly downloads, dependent count, security tooling multiplier. |
| `Tag Correlation` | Flags npm versions with no matching GitHub release or tag. |

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
| `chainrecon watch` | Monitor packages for new versions |
| `chainrecon version` | Print version info |

### scan flags

| Flag | Default | Description |
|---|---|---|
| `--format` | `table` | Output format (`table`, `json`, or `sarif`) |
| `--depth` | `20` | Number of versions to check for provenance history |
| `--threshold` | `0` | Exit code 1 if target score meets or exceeds this value |
| `--timeout` | `2m` | Request timeout |
| `--no-cache` | `false` | Bypass local cache |
| `--no-scorecard` | `false` | Skip OpenSSF Scorecard lookup |
| `--no-github` | `false` | Skip GitHub release/tag lookup |
| `--github-token` | | GitHub API token for higher rate limits |

### watch flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `.chainrecon.yml` | Path to watchlist YAML file |
| `--once` | `false` | Single pass mode for CI |
| `--state-file` | | Path to state file for persistence between runs |
| `--depth` | `20` | Number of versions to check per scan |
| `--timeout` | `2m` | Per-scan timeout |

`GITHUB_TOKEN` env var is supported for both commands.

## Build from source

```bash
git clone https://github.com/chainrecon/chainrecon.git
cd chainrecon
make build
./bin/chainrecon scan axios
```

## License

Apache 2.0. See [LICENSE](LICENSE).
