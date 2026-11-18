# Pinotechrd.Security.SampleApi

Minimal executable sample for consuming `Pinotechrd.Security` in an ASP.NET Core API.

It uses `PinotechrdSecurityDbContext` with `UsePinotechrdSecurity()`, one in-memory database per tenant (standing in for one schema per tenant), and one demo user per tenant: `alice@tenant-a.test` in `tenant-a` and `bob@tenant-b.test` in `tenant-b`, both with the password `Sample-Passw0rd`. Demo only: never ship fixed credentials.

## Run

```bash
dotnet run --project samples/Pinotechrd.Security.SampleApi/Pinotechrd.Security.SampleApi.csproj
```

## Endpoints

- `GET /health`
  - No tenant required
- `POST /api/auth/login`
  - Anonymous. Logs in through `IPinotechrdAuthManager` for the tenant in the `TenantId` header (`tenant-a`, `tenant-b`, case-exact).
- `POST /api/auth/refresh`
  - Anonymous. Refreshes through `IPinotechrdAuthManager`: the token is consumed atomically for the tenant in the `TenantId` header; presenting a used token again revokes its whole family.
- `GET /api/tenant`
  - Shows the resolved tenant. An authenticated user's tenant always comes from its token; the `TenantId` header is used only when no user is authenticated, and a user authenticated later by an endpoint-specific scheme must match it.
- `GET /api/secure`
  - Protected endpoint (`[Authorize]`) to validate middleware order and auth setup
- `GET /api/reports`
  - Permission-protected endpoint (`Sample.Read`): the token's tenant must match the resolved tenant.

## Quick Test

```bash
curl -H "TenantId: tenant-a" http://localhost:5000/api/tenant
```

## Hardened Flow Smoke Test

1. Log in:

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "TenantId: tenant-a" \
  -d '{"email":"alice@tenant-a.test","password":"Sample-Passw0rd"}'
```

1. The same user naming another tenant is refused (`401`): she does not exist in `tenant-b`'s database.

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "TenantId: tenant-b" \
  -d '{"email":"alice@tenant-a.test","password":"Sample-Passw0rd"}'
```

1. Access protected endpoints:

```bash
curl http://localhost:5000/api/secure -H "Authorization: Bearer <access-token>"
curl http://localhost:5000/api/reports -H "Authorization: Bearer <access-token>"
```

1. Rotate refresh token:

```bash
curl -X POST http://localhost:5000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -H "TenantId: tenant-a" \
  -d '{"refreshToken":"<refresh-token>"}'
```

1. Prove tenant claim precedence over conflicting header:

```bash
curl http://localhost:5000/api/tenant \
  -H "Authorization: Bearer <access-token>" \
  -H "TenantId: tenant-b"
```

Expected result: `tenant-a` is returned because the header is never read for an authenticated user.
