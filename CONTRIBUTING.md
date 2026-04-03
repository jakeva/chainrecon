# Contributing to chainrecon

## Getting started

```bash
git clone https://github.com/chainrecon/chainrecon.git
cd chainrecon
make build
make test
```

Requires Go 1.26+.

## Development workflow

1. Create a branch off `main`.
2. Make your changes.
3. Run `make test` and `make lint` locally before pushing.
4. Open a pull request against `main`.

CI runs tests, linting, and smoke scans on every PR. All checks must pass before merge.

## Running tests

```bash
make test          # unit tests with race detection
make lint          # golangci-lint
make vet           # go vet
make coverage      # generate coverage report
make integration-test  # integration tests (hits real APIs)
```

## Project layout

```
cmd/chainrecon/     Entry point
internal/
  cli/              Cobra commands, scan orchestration
  analyzer/         Signal analyzers (provenance, identity, blast radius, etc.)
  collector/        API clients (npm registry, GitHub, Scorecard)
  cache/            BoltDB cache layer
  model/            Shared types
  output/           Table and JSON formatters
pkg/                Public library code
```

## Code style

Go standard formatting (`gofmt`). The linter config handles the rest.

Keep error messages lowercase and prefixed with the package name (e.g., `npm: fetch metadata for %q: %w`).

## Commits

Write concise commit messages that describe what changed and why. Use conventional commit prefixes: `feat`, `fix`, `refactor`, `test`, `docs`, `perf`, `chore`.

## Adding a new analyzer

1. Create a file in `internal/analyzer/`.
2. Implement a function that takes the relevant model types and returns `[]model.Finding` and a score.
3. Wire it into the scan orchestration in `internal/cli/scan.go`.
4. Add tests.

## Adding a new collector

1. Create a package under `internal/collector/`.
2. Define an interface and a constructor that takes `cache.Store`.
3. Use `collector.NewHTTPClient()` for the HTTP client (shared transport).
4. Cache responses using the `cache.Store` with an appropriate TTL from `internal/cache/`.
5. Add tests using `httptest.NewServer`.

## Reporting issues

Open an issue on GitHub. Include the package you scanned, the output, and what you expected.
