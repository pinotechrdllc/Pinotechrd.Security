# Security Policy

## Supported Versions

Only preview versions have been published so far. Security fixes are released as a new preview; older previews are not patched.

| Version | Supported |
| --- | --- |
| Latest 1.2.0 preview | Yes |
| Older previews | No |

## Known Vulnerabilities

| Affected versions | Fixed in | Issue |
| --- | --- | --- |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | Tokens issued for the tenant named by the caller, without checking it against the resolved tenant; with per-tenant schemas, every context reused the first tenant's model, so a user of one tenant could obtain a token for another. |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | Two-factor sign-in not enforced at login, and the two-factor token was the user id, usable without the password. |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | Tenant taken from an unverified header, JSON body or query string; the request body was buffered without a size limit. |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | Refresh tokens: two concurrent refreshes could both succeed, reuse was not detected, sign-out and deactivation did not revoke them, and inactive users could refresh. |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | Login response time and messages revealed which accounts exist; inactive users could log in. |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | JWT issuer and audience not required, algorithm not pinned, key length counted in characters. |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | A bare permission name (for example `VIEW`) granted that permission in every module. |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | The tenant-id-to-schema mapping merged different ids (`a-b`, `a_b`, `A-B`) into one schema, so those tenants shared data. |
| `<= 1.2.0-preview.2` | `1.2.0-preview.3` | A user authenticated by an endpoint's own scheme ran with the tenant named in the request header. |

Upgrade to `1.2.0-preview.3` or later; see the changelog for the breaking changes and the migration steps.

## Reporting a Vulnerability

If you find a vulnerability, do not open a public issue first.

Please report privately with the following details:

- Affected package and version
- Impact and attack scenario
- Reproduction steps or proof of concept
- Suggested mitigation (if known)

Contact:

- [Open a private security advisory](https://github.com/pinotechrdllc/Pinotechrd.Security/security/advisories/new) in this repository. This is the only supported channel; it keeps the report private until a fix is available.

## Disclosure Process

1. Acknowledge report within 72 hours.
2. Confirm impact and reproduce.
3. Prepare fix and patch release.
4. Publish advisory and changelog notes after mitigation is available.

## Scope

In scope:

- Authentication and authorization bypasses
- Token validation weaknesses
- Multi-tenant isolation leaks
- Privilege escalation in role/permission flows

Out of scope:

- Vulnerabilities from unsupported package versions
- Issues requiring non-default insecure consumer configuration
