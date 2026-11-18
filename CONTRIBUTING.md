# Contributing

Thanks for contributing to Pinotechrd.Security.

## Quick Path

1. Fork and create a feature branch from `develop`.
2. Keep changes focused in small work units.
3. Add or update tests for behavior changes.
4. Open a pull request against `develop` with a clear summary.

## Development Notes

- Target framework: .NET 10
- Main packages:
  - `Pinotechrd.Security`
  - `Pinotechrd.Security.Abstractions`
- Version and package metadata are centralized in `Directory.Build.props`; package versions in `Directory.Packages.props`.
- Public API changes must be recorded in `PublicAPI.Unshipped.txt` (the build fails otherwise).
- `develop` is the integration branch. `main` only receives release merges, and releases are tagged from it.
- Every pull request runs the build, the test suite with its coverage gate, a vulnerability audit, CodeQL and a dependency review. All of them must pass, and a maintainer must approve, before a merge.

## Pull Request Checklist

- [ ] Scope is small and reviewable
- [ ] Tests added or updated
- [ ] No breaking API changes without documentation
- [ ] `CHANGELOG.md` updated when release behavior changes
- [ ] Documentation updated (`README`, `docs`, or both)

## Commit Style

Use Conventional Commits:

- `feat:` new functionality
- `fix:` bug fixes
- `docs:` documentation only
- `test:` test-only updates
- `ci:` workflow or automation changes

## Security

Do not disclose vulnerabilities in public issues.
Use [SECURITY.md](SECURITY.md) for responsible disclosure.
