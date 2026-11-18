# Pinotechrd.Security.SampleApi

Minimal executable sample for consuming `Pinotechrd.Security` in an ASP.NET Core API.

## Run

```bash
dotnet run --project samples/Pinotechrd.Security.SampleApi/Pinotechrd.Security.SampleApi.csproj
```

## Endpoints

- `GET /health`
  - No tenant required
- `POST /api/auth/token`
  - Issues access + refresh token for a valid tenant (`demo`, `tenant-a`, `tenant-b`)
- `POST /api/auth/refresh`
  - Validates opaque refresh token, revokes old token, returns rotated tokens
- `GET /api/tenant`
  - Resolves tenant from authenticated claim first; falls back to the `TenantId` header
- `GET /api/secure`
  - Protected endpoint (`[Authorize]`) to validate middleware order and auth setup

## Quick Test

```bash
curl -H "TenantId: demo" http://localhost:5000/api/tenant
```

## Hardened Flow Smoke Test

1. Issue token:

```bash
curl -X POST http://localhost:5000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"userId":"demo-user","tenantId":"tenant-a"}'
```

1. Access protected endpoint:

```bash
curl http://localhost:5000/api/secure \
  -H "Authorization: Bearer <access-token>"
```

1. Rotate refresh token:

```bash
curl -X POST http://localhost:5000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh-token>"}'
```

1. Prove tenant claim precedence over conflicting header:

```bash
curl http://localhost:5000/api/tenant \
  -H "Authorization: Bearer <refreshed-access-token>" \
  -H "TenantId: tenant-b"
```

Expected result: `tenant-a` is returned because authenticated claim is trusted before header fallback.
