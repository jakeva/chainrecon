# chainrecon

**Find the next supply chain attack before the attacker does.**

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/chainrecon/chainrecon/actions/workflows/ci.yml/badge.svg)](https://github.com/chainrecon/chainrecon/actions/workflows/ci.yml)

## What is chainrecon?

chainrecon is a supply chain reconnaissance tool for npm packages. It profiles packages from the attacker's perspective, identifying the signals that make a package an attractive target for compromise.

Every existing tool in this space is reactive. They flag known CVEs, detect malware after it ships, or score projects on general maintenance hygiene. None of them answer the question an attacker asks first: *which package should I target?*

The 2026 Trivy provenance bypass and the Axios maintainer account compromise both followed predictable patterns: high blast radius, weak publishing controls, concentrated maintainer access. These signals were visible before the attacks happened. chainrecon surfaces them proactively.

## Quick Start

```bash
go install github.com/chainrecon/chainrecon/cmd/chainrecon@latest
chainrecon scan axios
```

## Usage

```bash
# Scan a single package
chainrecon scan axios

# Scan with JSON output
chainrecon scan axios --format json

# Analyze the last 50 versions for provenance history
chainrecon scan axios --depth 50

# Set a custom timeout (default is 2 minutes)
chainrecon scan axios --timeout 5m

# Bypass the local response cache
chainrecon scan axios --no-cache

# Show version info
chainrecon version
```

Example output:

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
 │ Blast Radius            │ 10.0/10   │ Extremely high blast radius                 │
 ├─────────────────────────┼───────────┼─────────────────────────────────────────────┤
 │ Attack Surface          │ 7.4/10    │                                             │
 │ Target Score            │ 74.0      │ CRITICAL                                    │
 └─────────────────────────┴───────────┴─────────────────────────────────────────────┘

 Key Findings:
  [CRITICAL] Single maintainer with full publish access
  [CRITICAL] Maintainer email changed between versions
  [HIGH] Provenance is intermittent across versions
  [HIGH] All maintainers using personal email addresses
```

## Signals

chainrecon evaluates five signal categories in Phase 1, with OpenSSF Scorecard integration and GitHub tag correlation coming in Phase 2.

| Signal | What it measures |
|---|---|
| **Provenance Consistency** | Whether npm provenance attestations are present, and whether they have been dropped or appear intermittently across versions. A provenance drop is the single strongest indicator of compromise. |
| **Publishing Hygiene** | How packages are published: trusted publishing via CI/CD, direct token publish from a workstation, mixed methods, or legacy tokens. |
| **Maintainer Concentration** | How many npm accounts can publish, whether a single account controls all releases, and whether maintainers use personal or organizational email. |
| **Blast Radius** | Weekly downloads, dependent count, and ecosystem category (security tooling gets a 2x multiplier because compromising a scanner is strategically devastating). |
| **Identity Stability** | Maintainer email changes between versions, new publishers appearing on established packages, and anomalies in release cadence. |

## Scoring

chainrecon computes a target score that represents how attractive a package is from an attacker's perspective:

```
target_score = attack_surface_score × blast_radius_score
```

Each signal produces a 0.0 to 10.0 score. The attack surface score is a weighted average of the five signals. The target score ranges from 0.0 to 100.0.

| Rating | Score | Meaning |
|---|---|---|
| LOW | Below 25 | Strong provenance, distributed maintenance, limited blast radius |
| MEDIUM | 25 to 49 | Some gaps in publishing hygiene or moderate concentration risk |
| HIGH | 50 to 69 | Meaningful attack surface with significant downstream impact |
| CRITICAL | 70 and above | Weak controls and massive blast radius. This is what attackers look for. |

The score does not indicate that a package is compromised. It indicates how attractive the package would be as a target.

## How it would have caught the 2026 attacks

**Trivy (March 2026):** TeamPCP exploited a `pull_request_target` workflow to steal a PAT, force pushed malicious commits across 76 version tags, and deployed the CanisterWorm worm to 47+ packages. chainrecon would have flagged the single maintainer concentration and the provenance gaps that preceded the attack.

**Axios (March 2026):** A North Korea nexus actor hijacked the lead maintainer's npm account, changed the account email, and published malicious versions without provenance. The legitimate versions had OIDC provenance and SLSA attestations. The malicious ones had none. chainrecon's provenance state machine would have detected the DROPPED state immediately, and the identity analyzer would have flagged the email change.

## Comparison with existing tools

| Feature | chainrecon | OpenSSF Scorecard | Socket | Snyk |
|---|---|---|---|---|
| **Approach** | Proactive attacker modeling | General project health | Install time behavior analysis | Known vulnerability database |
| **npm Provenance Tracking** | Deep, across versions | Basic check | No | No |
| **Blast Radius Weighting** | Core signal | Not weighted | Not a factor | Not a factor |
| **Maintainer Risk Analysis** | Bus factor, concentration | Contributor count only | Limited | No |
| **Publishing Hygiene** | Token type, publish method | Partial (branch protection) | No | No |
| **Focus** | "Which package would I target?" | "Is this project well maintained?" | "Is this install safe?" | "Does this have known CVEs?" |

chainrecon is complementary to Scorecard, not competitive. Phase 2 will import Scorecard data as one input signal (weighted at 15% of the composite score). The novel 85% comes from npm specific signals that Scorecard cannot access because it evaluates repositories, not registry packages.

## Roadmap

**Phase 2:** OpenSSF Scorecard data integration. GitHub release tag to npm version correlation (detecting versions published without a corresponding GitHub release, which is exactly what happened with Axios). Watch mode for continuous monitoring.

**Phase 3:** SARIF output for CI/CD integration. Webhook alerts for signal changes. Lockfile scanning for `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`.

**Future:** PyPI and crates.io support. Maintainer relationship graph analysis. MCP server for inline supply chain review during development. Public ecosystem dashboard.

## Building from source

```bash
git clone https://github.com/chainrecon/chainrecon.git
cd chainrecon
make build
./bin/chainrecon scan axios
```

## License

Apache License 2.0. See [LICENSE](LICENSE) for the full text.
