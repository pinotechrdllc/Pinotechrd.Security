# NuGet Rollback Runbook

## Purpose

This runbook defines the rollback path when a published package version must be reverted.

## Scope

- Packages: Pinotechrd.Security and Pinotechrd.Security.Abstractions
- Registry: [NuGet.org](https://www.nuget.org)

## Trigger Conditions

- Critical runtime regression in authentication, authorization, or tenancy behavior.
- Security issue discovered after publish.
- Broken package metadata or dependency issue in a released version.

## Strict Token Hardening Advisory

This release family includes stricter runtime behavior:

- Refresh token validation is opaque/store-based and rotates on success.
- JWT secret minimum length is enforced at startup.
- Tenant resolution trusts authenticated claims first and ignores unsigned bearer payload parsing.

If consumers report authentication breakage after upgrading, triage these three checks before deciding rollback:

1. JWT secret length and non-empty configuration.
2. Refresh flow integration against current token persistence strategy.
3. Middleware order (`UseAuthentication` before `UseTenantResolution`).

## Rollback Steps

1. Identify affected version (`X.Y.Z`) and impacted package(s).
2. Unlist the affected package version(s) in NuGet gallery.
3. Communicate advisory to consumers with mitigation and expected patch ETA.
4. Prepare patch in next version (`X.Y.(Z+1)`) with fix.
5. Update `Directory.Build.props` version and `CHANGELOG.md` section.
6. Push release tag (`vX.Y.(Z+1)`) and let the `Release` workflow run.
7. Verify both packages are available and metadata is correct.
8. Post-release confirmation to stakeholders.

## Validation Checklist

- Both packages have same published version.
- Changelog contains exact released version heading.
- CI test and coverage gate passed before publish.
- NuGet package README and symbols are present.
- Advisory impact and mitigation documented for token/tenant behavior changes.

## Strict Behavior Rollback Notes

When rollback is required due to strict-token behavior incompatibility:

1. Unlist the affected version(s) immediately.
2. Publish a patch version with temporary compatibility guidance or migration fix.
3. Include explicit consumer migration notes in `CHANGELOG.md` and release notes.
4. Re-run test suite and smoke-check auth/refresh/tenant paths before retagging.

## Communication Template

- Issue summary:
- Affected versions:
- Action taken (unlisted):
- Fixed version:
- Consumer action required:
