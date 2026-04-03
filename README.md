# chainrecon

**Predict the next supply chain attack.**

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

# Provide a GitHub token for higher API rate limits
chainrecon scan axios --github-token ghp_xxx
# Or set via environment variable
export GITHUB_TOKEN=ghp_xxx

# Skip Scorecard or GitHub lookups
chainrecon scan axios --no-scorecard
chainrecon scan axios --no-github

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

chainrecon evaluates six signal categories, combining npm registry analysis with imported data from OpenSSF Scorecard and GitHub.

| Signal | What it measures |
|---|---|
| **Provenance Consistency** | Whether npm provenance attestations are present, and whether they have been dropped or appear intermittently across versions. A provenance drop is the single strongest indicator of compromise. |
| **Publishing Hygiene** | How packages are published: trusted publishing via CI/CD, direct token publish from a workstation, mixed methods, or legacy tokens. |
| **Maintainer Concentration** | How many npm accounts can publish, whether a single account controls all releases, and whether maintainers use personal or organizational email. |
| **Blast Radius** | Weekly downloads, dependent count, and ecosystem category (security tooling gets a 2x multiplier because compromising a scanner is strategically devastating). |
| **Identity Stability** | Maintainer email changes between versions, new publishers appearing on established packages, and anomalies in release cadence. |
| **OpenSSF Scorecard** | Imported from scorecard.dev and inverted so higher means more vulnerable, matching chainrecon's convention. Surfaces individual check failures for Dangerous Workflow, Token Permissions, Pinned Dependencies, Branch Protection, and Signed Releases. Weighted at 15% of the composite score. |

chainrecon also performs **tag correlation** between npm versions and GitHub releases/tags. Versions published without a corresponding GitHub tag are flagged as findings, since this is the exact pattern seen in the Axios compromise where malicious versions had no GitHub release.

## Scoring

chainrecon computes a target score that represents how attractive a package is from an attacker's perspective:

```
target_score = attack_surface_score × blast_radius_score
```

Each signal produces a 0.0 to 10.0 score. The attack surface score is a weighted average of the signals. When Scorecard data is available, it receives 15% weight and the other four signals share the remaining 85%. When Scorecard is unavailable, the original four signal weights are used. The target score ranges from 0.0 to 100.0.

| Rating | Score | Meaning |
|---|---|---|
| LOW | Below 25 | Strong provenance, distributed maintenance, limited blast radius |
| MEDIUM | 25 to 49 | Some gaps in publishing hygiene or moderate concentration risk |
| HIGH | 50 to 69 | Meaningful attack surface with significant downstream impact |
| CRITICAL | 70 and above | Weak controls and massive blast radius. This is what attackers look for. |

The score does not indicate that a package is compromised. It indicates how attractive the package would be as a target.

## How it would have caught the 2026 attacks

**Trivy (March 2026):** TeamPCP exploited a `pull_request_target` workflow to steal a PAT, force pushed malicious commits across 76 version tags, and deployed the CanisterWorm worm to 47+ packages. chainrecon would have flagged the single maintainer concentration and the provenance gaps that preceded the attack.

**Axios (March 2026):** A North Korea nexus actor hijacked the lead maintainer's npm account, changed the account email, and published malicious versions without provenance. The legitimate versions had OIDC provenance and SLSA attestations. The malicious ones had none. chainrecon's provenance state machine would have detected the DROPPED state immediately, the identity analyzer would have flagged the email change, and tag correlation would have flagged the missing GitHub releases.

## Comparison with existing tools

| Feature | chainrecon | OpenSSF Scorecard | Socket | Snyk |
|---|---|---|---|---|
| **Approach** | Proactive attacker modeling | General project health | Install time behavior analysis | Known vulnerability database |
| **npm Provenance Tracking** | Deep, across versions | Basic check | No | No |
| **Blast Radius Weighting** | Core signal | Not weighted | Not a factor | Not a factor |
| **Maintainer Risk Analysis** | Bus factor, concentration | Contributor count only | Limited | No |
| **Publishing Hygiene** | Token type, publish method | Partial (branch protection) | No | No |
| **Scorecard Integration** | Imported as weighted signal | N/A | No | No |
| **Tag Correlation** | npm to GitHub release/tag matching | No | No | No |
| **Focus** | "Which package would I target?" | "Is this project well maintained?" | "Is this install safe?" | "Does this have known CVEs?" |

chainrecon imports Scorecard data as one input signal (weighted at 15% of the composite score). The novel 85% comes from npm specific signals that Scorecard cannot access because it evaluates repositories, not registry packages.

## Roadmap

**Phase 1 (complete):** Core npm signal analysis with provenance tracking, publishing hygiene, maintainer risk, identity stability, and blast radius scoring.

**Phase 2 (complete):** OpenSSF Scorecard integration and GitHub tag correlation. Scorecard scores are imported and inverted, with individual check failures surfaced as findings. Tag correlation detects npm versions published without corresponding GitHub releases or tags.

**Phase 3:** Watch mode for continuous monitoring. SARIF output for CI/CD integration. GitHub Actions support for PR dependency scanning and scheduled monitoring.

**Phase 4:** Release time detection. Tarball diffing between versions, lifecycle script injection detection, new dependency injection detection, obfuscation signal analysis, and network call introduction flagging. All deterministic analysis with optional LLM pass.

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
