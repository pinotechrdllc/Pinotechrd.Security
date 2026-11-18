# Security Policy

## Supported Versions

Only preview versions have been published so far. Security fixes are released as a new preview; older previews are not patched.

| Version | Supported |
| --- | --- |
| Latest 1.2.0 preview | Yes |
| Older previews | No |

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
