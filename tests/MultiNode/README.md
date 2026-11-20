# Multi-node validation of Pinotechrd.Security

Runs the library from this repository (`src/`) on **two nodes** with no production platform:
disposable local containers and synthetic data only.

```powershell
.\run.ps1                         # both schema modes
.\run.ps1 -Mode SearchPath        # one mode
.\run.ps1 -Mode SearchPath -KeepRunning   # leave containers and nodes up to explore
```

Requires Docker, PowerShell 7 and the .NET 10 SDK. CI runs it in the `multinode` job on every pull request and push. Ports: PostgreSQL 57432, PgBouncer 57433, Redis 57379, nodes 5101 and 5102.
Logs and TRX results go to `logs\`.

## What runs

| Piece | Setup |
|---|---|
| PostgreSQL 17.7 | owner role `sec_owner` (provisioning only); one login role per tenant (`tenant_acme_app`, `tenant_globex_app`) and a catalog reader (`catalog_app`), none superuser, as README "Database roles and poolers" describes |
| PgBouncer 1.26 | session mode, one user per role; the nodes reach PostgreSQL only through it |
| Redis 7.4 | `IDistributedCache` shared by both nodes (tenant subscription cache, two-factor codes of the test message sink) |
| Two nodes | separate processes of `MultiNodeHost` in the **Production** environment, each with its own memory; shared: the database, Redis, the Data Protection key folder and a random signing secret generated per run |
| Stores | EF Core refresh tokens and two-factor attempts in each tenant's schema; no in-memory store, no opt-out |

Provisioning (`MultiNodeHost provision`) is what a deployment pipeline does with the owner role: the README's
`ProvisionTenantAsync` per tenant, then the grants.

## Scenarios (`MultiNodeTests`)

Each starts on one node and checks the effect on the other:

1. The two nodes are separate processes in the expected schema mode.
2. A token issued on one node is accepted on the other, with its permission.
3. Sign-out on one node ends the session on the other at once (`401 session_revoked`), and its refresh token.
4. An administrative revocation on one node ends the session on the other.
5. A refresh token replayed on the other node revokes the whole family.
6. Two-factor started on one node (token protected with the shared keys) and finished on the other; the challenge is single use everywhere.
7. Five wrong two-factor codes split across the nodes spend the challenge (per-node counters would allow ten).
8. A plan change invalidated on one node applies on the other at once (shared cache generation).
9. Raw SQL that names another tenant's schema is refused by the tenant's database role (`42501`) on both nodes.
10. A user of one tenant cannot sign in to the other; a token stays in its tenant whatever header is sent.
11. 200 interleaved requests of both tenants on both nodes, through pooled sessions, each read only their own tenant.

The `/admin` and `/test` endpoints of the host exist only for this validation and are not protected.
