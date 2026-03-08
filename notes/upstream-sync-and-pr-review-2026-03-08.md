# Upstream sync and PR review notes (2026-03-08)

## Best practices for this project

- Keep PR scope narrow: one concern per PR (tests vs runtime/dependency/CI changes).
- For coverage PRs, change only tests unless maintainers explicitly ask otherwise.
- Keep branch up to date with `upstream/master` before opening or refreshing PRs.
- Preserve Python compatibility declared in `pyproject.toml` and docs; avoid surprise dependency policy changes in unrelated PRs.
- For connector tests, assert side effects fully (e.g. API calls and `execute()` when required), not just method chaining.
- Treat build/security automation as a separate track: changes to Docker, workflows, and dependency pinning should be reviewed independently.
- Maintain sample-based and unit coverage balance; avoid test-only assertions that can pass while runtime behavior is still broken.

## Possible development directions

- Improve connector correctness tests for Gmail/Graph/IMAP with stronger behavioral assertions and negative-path coverage.
- Add targeted runtime fixes where tests exposed issues (example: Gmail delete call execution path).
- Split operational hardening into dedicated PRs:
  - CI security scans
  - weekly image build/SBOM/scanning
  - dependency pinning and supply-chain controls
- Expand typing and API consistency work to reduce integration regressions.
- Increase coverage for DMARCbis edge cases and parser compatibility changes.
- Introduce smaller, topic-focused PR cadence to speed upstream review and merge turnaround.

## PR feedback summary

### PR #664 (Increase unit test coverage for Gmail/Graph/IMAP connectors)

- Maintainer feedback: keep PR strictly test-only, split non-test changes into separate PRs.
- Review comments flagged scope mismatch:
  - test-only description vs added workflow/CI changes
  - test-only description vs dependency constraint changes
- Review comments flagged security/process concerns:
  - unpinned build tooling in Docker image process
- Test quality note:
  - Gmail delete path test should likely assert `.execute()` call too.

### PR #662 (Fix Python 3.14 support metadata and require imapclient 3.1.0)

- Merged successfully.
- Codecov patch status was green; project status warning was stale-base related.
- No maintainer blocking comments recorded on code changes.

## Branches prepared locally

- `sync/master-upstream-2026-03-08` (merged with `upstream/master`, conflict preference: local branch changes)
- `sync/dmarcbis-upstream-2026-03-08` (merged with `upstream/master`, conflict preference: local branch changes)
- `sync/draft-test-coverage-upstream-upstream-2026-03-08` (merged with `upstream/master`, conflict preference: local branch changes)
- `sync/upstream-py314-imapclient-fix-upstream-2026-03-08` (merged with `upstream/master`, conflict preference: local branch changes)
- `coverage-only-upstream-2026-03-08` (based on `upstream/master`, contains only test coverage commit from PR #664)
