# Pinotechrd.Security.SampleApi

A runnable API on the setup the library recommends, meant to be copied:

- **PostgreSQL**, one schema per tenant (`SearchPath` mode). The application logs in as `sample_app`, which is not a superuser and cannot create anything; the owner role only provisions.
- **The library's defaults**: `AddPinotechrdCatalogTenantStore` (active tenants from the catalog) and the default `ISecurityDataProvider` (the user of the library's token, the resolved tenant, roles and permissions from the tenant's tables). The real subscription and module checks.
- **Durable session state**: refresh tokens and two-factor attempts in each tenant's schema, Data Protection keys persisted.
- **Configuration**, not code, for secrets: the JWT secret, connection strings and key folder.

It starts outside Development too: the library refuses in-memory stores and unpersisted keys there, and this setup has neither.

## Run

Requires Docker and the .NET 10 SDK.

```bash
cd samples/Pinotechrd.Security.SampleApi
docker compose up -d          # PostgreSQL 17.7 on localhost:55440, roles from init-roles.sql
dotnet run                    # Development: provisions two tenants on first start
```

`appsettings.Development.json` holds local, development-only values. Outside Development, set them from a secret store:
`ConnectionStrings__Security`, `Security__JwtSecret` (at least 32 random bytes), `Security__KeysPath` (storage every instance shares), and provision with your deployment pipeline instead of at start.

`docker compose down -v` removes the database; delete the `.keys` folder to start over.

## What is provisioned (Development)

| Tenant (`TenantId` header) | User | Role | Notes |
|---|---|---|---|
| `tenant-a` | `alice@tenant-a.test` | seller (`SALES.VIEW`) | |
| `tenant-a` | `carol@tenant-a.test` | none | gets `403` on `/api/sales` |
| `tenant-a` | `mfa@tenant-a.test` | seller | two-factor by email; the code is written to the log |
| `tenant-b` | `bob@tenant-b.test` | seller | |

Password: `Sample-Passw0rd!` (demo only). Each tenant's plan includes the `SALES` module.

## Walk-through

```bash
# Sign in (the tenant must exist and be active in the catalog)
curl -s -X POST http://localhost:5000/api/auth/login -H "TenantId: tenant-a" -H "Content-Type: application/json" \
  -d '{"email":"alice@tenant-a.test","password":"Sample-Passw0rd!"}'

# Permission-protected: plan has SALES and the role grants SALES.VIEW -> 200; carol -> 403
curl -s http://localhost:5000/api/sales -H "TenantId: tenant-a" -H "Authorization: Bearer <accessToken>"
curl -s http://localhost:5000/api/permissions -H "TenantId: tenant-a" -H "Authorization: Bearer <accessToken>"

# A user of tenant-b naming tenant-a -> 401; an unknown tenant -> 400
curl -s -X POST http://localhost:5000/api/auth/login -H "TenantId: tenant-a" -H "Content-Type: application/json" \
  -d '{"email":"bob@tenant-b.test","password":"Sample-Passw0rd!"}'

# Two-factor: login returns twoFactorToken; send the code, read it in the log, verify
curl -s -X POST http://localhost:5000/api/auth/2fa/send -H "TenantId: tenant-a" -H "Content-Type: application/json" \
  -d '{"token":"<twoFactorToken>","provider":"Email"}'
curl -s -X POST http://localhost:5000/api/auth/2fa/verify -H "TenantId: tenant-a" -H "Content-Type: application/json" \
  -d '{"token":"<twoFactorToken>","provider":"Email","code":"<code>"}'

# Refresh (single use: replaying a used refresh token revokes its family)
curl -s -X POST http://localhost:5000/api/auth/refresh -H "TenantId: tenant-a" -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshToken>"}'

# Sign out: every session ends; the same access token now gets 401 session_revoked
curl -s -X POST http://localhost:5000/api/auth/logout -H "TenantId: tenant-a" -H "Authorization: Bearer <accessToken>"
curl -s http://localhost:5000/api/me -H "TenantId: tenant-a" -H "Authorization: Bearer <accessToken>"
```

## Going further

- **One database role per tenant** for isolation against hostile SQL, and **poolers**: library README, "Database roles and poolers".
- **Several instances**: register a shared `IDistributedCache` (for example Redis) and store the Data Protection keys where every instance reads them.
- **Rate limiting** of sign-in, two-factor and refresh is the host's: library README, "For operators".
