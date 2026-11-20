# Step-by-Step Guide: Publish Pinotechrd.Security to nuget.org

This repository publishes two packages from one tag:

- `Pinotechrd.Security.Abstractions`
- `Pinotechrd.Security` (depends on `Pinotechrd.Security.Abstractions` with the same version)

Publishing is done by [.github/workflows/release.yml](../.github/workflows/release.yml) using
[nuget.org Trusted Publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing):
GitHub issues a short-lived OIDC token, nuget.org exchanges it for an API key valid for one hour,
and the workflow pushes with it. No API key is stored in GitHub.

Packages are not author-signed. nuget.org repository-signs every package it receives
(["all packages uploaded to nuget.org are automatically repository signed"](https://learn.microsoft.com/nuget/reference/signed-packages-reference)).

## How a release runs

The `Release` workflow starts only when a tag matching `v*` is pushed. It:

1. Fails unless the tag equals `v` + `<Version>` from [Directory.Build.props](../Directory.Build.props).
2. Fails unless [CHANGELOG.md](../CHANGELOG.md) has a `## [<Version>]` section.
3. Fails unless the tagged commit is on `main`.
4. Job `build` (read-only): restores, audits vulnerable packages (High/Critical blocks), builds with warnings as errors, runs tests with the coverage gate, packs, and generates a CycloneDX SBOM per package (shipped dependencies only; the tool version is in `.config/dotnet-tools.json`). It uploads the packages and SBOMs as the run's artifact.
5. Job `publish` (environment `nuget-production`; `id-token` and `attestations` write): attests the build provenance of the built `.nupkg`/`.snupkg` files and each SBOM against its `.nupkg` (GitHub artifact attestations, signed with Sigstore), requests a temporary API key with `NuGet/login@v1` and pushes Abstractions first, then the main package. Each `.snupkg` is pushed with its `.nupkg`.
6. Job `release` (`contents`, `id-token` and `attestations` write): downloads the packages nuget.org serves, which carry its repository signature, and fails unless their content equals what `build` produced (only `.signature.p7s`, which nuget.org adds, may differ). It then attests the provenance and the SBOM of those signed files, so the packages consumers download verify, and creates the GitHub Release of the tag with the published packages, the symbol packages, the SBOMs and `SHA256SUMS`. It waits up to 30 minutes for nuget.org to validate and sign a package.

No code from the repository's dependencies runs in a job that holds a write permission.

### If a release fails after the push

The packages are then public, but may lack the attestations of the published files or the GitHub Release. Do not push a new tag: open the failed run and use **Re-run failed jobs**. Only the failed job and the ones after it run again, on the same run's artifacts; `publish` skips packages that are already on nuget.org (`--skip-duplicate`), and `release` uploads to an existing GitHub Release instead of failing.

---

## Part 1: One-time setup

### 1) nuget.org account or organization

Decide which nuget.org owner will own the packages (your nuget.org user or a nuget.org organization). The Trusted Publishing policy applies to all packages owned by that owner.

### 2) Trusted Publishing policy on nuget.org

nuget.org → your user name → **Trusted Publishing** → add a policy:

| Field | Value |
| --- | --- |
| Policy owner | The nuget.org user or organization that will own the packages |
| Repository Owner | `pinotechrdllc` (GitHub organization) |
| Repository | `Pinotechrd.Security` |
| Workflow File | `release.yml` (file name only) |
| Environment | `nuget-production` |

For a private repository the policy can start as "temporarily active" for 7 days and becomes permanent after the first successful publish.

### 3) GitHub environment and variable

1. GitHub → repository → **Settings → Environments** → create or keep `nuget-production`. Adding required reviewers is recommended.
2. GitHub → repository → **Settings → Secrets and variables → Actions → Variables** → add `NUGET_USER` with your nuget.org **profile name** (not your email). It is not a secret.

### 4) Reserve the package ID prefix (recommended)

Email `account@nuget.org` with the nuget.org owner display name and the prefix `Pinotechrd.`
([ID prefix reservation](https://learn.microsoft.com/nuget/nuget-org/id-prefix-reservation)). Once granted, packages matching
`Pinotechrd.*` from other owners are rejected and yours show the reserved-prefix checkmark.

---

## Part 2: Every release

1. Set `<Version>` in [Directory.Build.props](../Directory.Build.props), e.g. `1.2.0`.
2. Add `## [1.2.0] - YYYY-MM-DD` to [CHANGELOG.md](../CHANGELOG.md).
3. Move the entries of each `PublicAPI.Unshipped.txt` into the matching `PublicAPI.Shipped.txt` when releasing a stable version.
4. Open a PR, wait for `CI`, merge to `main`.
5. Tag the merge commit and push the tag:

   ```bash
   git switch main && git pull
   git tag v1.2.0
   git push origin v1.2.0
   ```

6. Follow the `Release` run in GitHub Actions and confirm both packages on nuget.org.

After the first **stable** release, set `PackageValidationBaselineVersion` in
[Directory.Build.props](../Directory.Build.props) to that version so `dotnet pack` fails on breaking changes.

---

## Local validation (same checks as CI)

```bash
dotnet restore Pinotechrd.Security.slnx
pwsh ./build/audit-vulnerable-packages.ps1 -ReportPath ./artifacts/nuget-vulnerability-report.json
dotnet build Pinotechrd.Security.slnx -c Release --no-restore -warnaserror
dotnet test tests/Pinotechrd.Security.Tests/Pinotechrd.Security.Tests.csproj -c Release --no-build /p:CollectCoverage=true /p:CoverletOutputFormat=cobertura '/p:Include=[Pinotechrd.Security]Pinotechrd.Security.*' /p:Threshold=40 /p:ThresholdType=line /p:ThresholdStat=total
dotnet pack src/Pinotechrd.Security.Abstractions/Pinotechrd.Security.Abstractions.csproj -c Release --no-build -o ./artifacts
dotnet pack src/Pinotechrd.Security/Pinotechrd.Security.csproj -c Release --no-build -o ./artifacts
```

`artifacts/` is ignored by git.

---

## Troubleshooting

| Failure | Meaning | Fix |
| --- | --- | --- |
| `Tag vX does not match version vY` | Tag and `Directory.Build.props` differ | Delete the tag, fix the version or tag the right commit |
| `CHANGELOG.md has no '## [X]' section` | Missing release notes | Add the exact heading |
| `Tagged commit ... is not on main` | Tag was created on a branch | Merge first, tag the commit on `main` |
| `High/Critical vulnerable packages detected.` | Blocking advisory | Upgrade the dependency |
| Coverage threshold failure | Line coverage under 40 % | Add tests |
| `NuGet/login` fails | Policy fields do not match the run | Check owner, repository, workflow file name, environment and `NUGET_USER` |
| `403` on push | Package owned by another account or prefix reserved by someone else | Check ownership on nuget.org |
