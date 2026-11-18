# NuGet Production Checklist

## Preconditions

- [ ] Version is set once in `Directory.Build.props`.
- [ ] `CHANGELOG.md` contains a `## [X.Y.Z]` section for the release version.
- [ ] Package metadata (id, description, license, README) validated in a local `dotnet pack`.
- [ ] `CI` is green on `main`.
- [ ] Trusted Publishing policy exists on nuget.org for `pinotechrdllc/Pinotechrd.Security`, workflow `release.yml`, environment `nuget-production`.
- [ ] Repository variable `NUGET_USER` is set to the nuget.org profile name.
- [ ] For stable releases: `PublicAPI.Unshipped.txt` entries moved to `PublicAPI.Shipped.txt`.

## Release Steps

1. Merge release changes to `main`.
2. Push the tag `vX.Y.Z` on the merged commit.
3. Confirm the `Release` workflow succeeded.
4. Verify both packages are published with identical version and that `Pinotechrd.Security` depends on `Pinotechrd.Security.Abstractions` with the same version.
5. Validate README, symbols and Source Link on nuget.org (the package page shows "Source Link: Valid").

See [NUGET_PUBLISH_STEP_BY_STEP.md](NUGET_PUBLISH_STEP_BY_STEP.md) for details.

## Rollback

1. Unlist the affected package version on nuget.org.
2. Prepare patch version (`X.Y.Z+1`) with the fix.
3. Merge to `main` and push tag `vX.Y.(Z+1)`.

## Ownership by Lane

- Lane A (Packaging): metadata and version policy.
- Lane B (Testing): critical coverage and release confidence.
- Lane C (CI): pull request quality gates.
- Lane D (Release): tag-driven publish workflow and Trusted Publishing policy.
- Lane E (Docs): runbooks and migration notes.
