# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [Unreleased]

### Added

- `AddPinotechrdEfRefreshTokenStore<TContext>()`: an opt-in, scoped `IRefreshTokenStore` kept in each tenant's schema through EF Core, replacing the default `InMemoryRefreshTokenStore`. Tokens are stored as SHA-256 hashes, consumed with one conditional `UPDATE`, and a replayed token revokes its family. Requires `PinotechrdSecurityModelOptions.MapRefreshTokens` (default `false`, so the model of existing applications does not change); applications that enable it add their own migration for the `refresh_tokens` and `refresh_token_families` tables.
- `AddPinotechrdEfTwoFactorAttemptStore<TContext>()`: an opt-in, scoped `ITwoFactorAttemptStore` kept in each tenant's schema through EF Core, replacing the default `InMemoryTwoFactorAttemptStore`, so a two-factor token allows five attempts in total across instances and restarts. Each attempt is one atomic `UPDATE count = count + 1`; challenge ids are stored as SHA-256 hashes. Requires `PinotechrdSecurityModelOptions.MapTwoFactorAttempts` (default `false`); applications that enable it add their own migration for the `two_factor_attempts` table. The store throws inside a database transaction or `TransactionScope`, because a rollback would erase the counted attempts.
- `IPinotechrdSessionPurger`, registered by both EF store registrations: `PurgeExpiredAsync(margin)` deletes, in the current tenant's schema, the refresh token families whose tokens all expired more than the margin ago (default one hour), the family rows left without tokens, and the two-factor attempts expired more than the margin ago, returning the counts in `SessionPurgeResult`. A used token is kept while its family has a live token, so its replay is still detected. Only mapped tables are purged; run it per tenant from a scheduled job. The margin cannot be shorter than IPinotechrdSessionPurger.MinimumMargin (five minutes), and both EF stores must be registered with the same context.
- `ISecurityCacheInvalidator.InvalidateTenantAsync(tenantId)` (in `Pinotechrd.Security.Abstractions`, registered as a scoped service): drops a tenant's cached subscription state and module codes, so the next check reads fresh data on every instance that shares the distributed cache. Other tenants are untouched. Call it after committing a subscription, plan or module change.
- `PinotechrdSecurityOptions.TenantCacheExpiration` (default 5 minutes, must be positive): how long those entries are cached.
- `PinotechrdSecurityOptions.SetDefaultAuthenticationSchemes` (default `true`, the previous behaviour). Set it to `false` to keep the host's own default schemes (for example cookies or OpenID Connect set through `DefaultScheme`): the JWT bearer scheme and its enforced validation settings are still registered, but `AddPinotechrdSecurity` sets no default, and clears the `DefaultAuthenticateScheme`/`DefaultChallengeScheme` (`Identity.Application`) and `DefaultSignInScheme` (`Identity.External`) that `AddIdentity` sets, only while they still hold those values; both used to override the host's `DefaultScheme`. The value is read from `IOptions<PinotechrdSecurityOptions>`, so a later `Configure<PinotechrdSecurityOptions>` or configuration binding is honoured. With the flag off, the tenant middleware reads the principal of the host's default scheme: a request carrying only a bearer token is anonymous there and must send the tenant header, unless the default is a policy scheme whose `ForwardDefaultSelector` picks JWT bearer when an `Authorization: Bearer` header is present. For schemes other than the library's JWT bearer, the host is responsible for a membership-verified tenant claim and for exempting it from inbound claim mapping. The `UseTenantResolution()` ordering check now also fires when the JWT bearer scheme is registered but is not the default.
- `IPinotechrdSecurityManager.RevokeUserSessionsAsync(userId)`: administrative sign-out of any user; revokes all its refresh tokens and renews its security stamp. Returns `false` when the user is not found or no `IRefreshTokenStore` is registered.
- `ISecurityEngine.GetCurrentUserPermissionsAsync()`: the permissions of the authenticated user (`ISecurityDataProvider.GetCurrentUserId()`), empty when there is none.
- **JWT key rotation.** `JwtSettings.PreviousSecrets` (default empty): secrets accepted when validating access tokens (bearer authentication and `GetPrincipalFromExpiredToken`), never used to sign. Each entry must meet the same minimum length as `Secret`, and must not be empty, equal to `Secret`, or repeated, or options validation fails. Rotate across instances in three deployments: add the new secret to `PreviousSecrets` everywhere; make it `Secret` and move the old one to `PreviousSecrets`; remove the old one once its tokens are no longer needed (access tokens expired and the refresh window over). No time limit is enforced, keys are read only at startup (each step needs a restart), and a leaked secret must never stay in `PreviousSecrets`: it can forge tokens, and `GetPrincipalFromExpiredToken` accepts them at any age.

### Changed (breaking)

- **JWT.** Access tokens carry a `kid` header: the first 16 lowercase hex characters of SHA-256 over the signing secret's UTF-8 bytes. The bearer handler's validation keys are set with `TokenValidationParameters.IssuerSigningKeys` (current secret first, then `PreviousSecrets`), and, after all `Configure<JwtBearerOptions>` calls, `IssuerSigningKey`, `IssuerSigningKeyResolver`, `IssuerSigningKeyResolverUsingConfiguration`, `SignatureValidator`, `SignatureValidatorUsingConfiguration` and `TokenValidationParameters.ConfigurationManager` are set to `null`, as are `JwtBearerOptions.Configuration` and `JwtBearerOptions.ConfigurationManager`: only the configured secrets are accepted. A key, resolver or signature validator the application set, and keys from OpenID Connect metadata (`Authority`, `MetadataAddress`), are no longer used. Tokens issued before the upgrade have no `kid` and still validate against the same secret.
- **Self-service APIs.** `IPinotechrdAuthManager.SignOutAsync(userId)` and `ChangePasswordAsync(userId, currentPassword, newPassword)` are removed: they looked like self-service but acted on any user id the caller passed (an IDOR risk). Use `SignOutCurrentUserAsync()` (returns `Task<bool>`) and `ChangeOwnPasswordAsync(currentPassword, newPassword)` (returns `AuthResult`), which act on the authenticated user from `ISecurityDataProvider.GetCurrentUserId()` and change nothing when there is none or it is not found. `PinotechrdAuthManager` gains an optional `ISecurityDataProvider` constructor parameter, which `AddPinotechrdSecurity` resolves from the application's registration. For administrative use, call `IPinotechrdSecurityManager.RevokeUserSessionsAsync(userId)` and `ChangeUserPasswordAsync(userId, ...)`, and authorize the caller first. Every `userId` member of `IPinotechrdSecurityManager` and `ISecurityEngine.GetPermissionsAsync(userId)` is documented as administrative. See "Self-service vs administrative APIs" in the README.
- **Tenant cache.** `TenantCacheStore` caches through `IDistributedCache` instead of `IMemoryCache`; its constructor is now `TenantCacheStore(ISecurityStore, IDistributedCache, IOptions<PinotechrdSecurityOptions>)`, and it implements `ISecurityCacheInvalidator`. `AddPinotechrdSecurity` adds the in-memory distributed cache only when no `IDistributedCache` is registered (an application's Redis or SQL Server cache wins, registered before or after), and no longer calls `AddMemoryCache()`: an application that resolves `IMemoryCache` must register it itself. Entries expire after 5 minutes instead of 15, and `IsModuleActiveAsync` is answered from the cached active module codes instead of its own query. Before, a cancelled subscription or disabled module kept granting access for up to 15 minutes on every instance, with no way to clear it. With several instances, register a shared `IDistributedCache`, or an invalidation reaches only the instance that made it.
- Options validation fails when tenant membership cannot be relied on and no `IIdentityValidator<TUser>` is registered. Membership is relied on only when the context passed to `AddPinotechrdSecurity` derives from `PinotechrdSecurityDbContext<TUser, TRole>`, its registered options use `UsePinotechrdSecurity()`, and in `SearchPath` mode `ApplicationTakesResponsibilityForSearchPath` is off; the message names the context and the condition that failed. Before, a user of one tenant could obtain a token for another tenant in the other setups. The check runs when the host starts and on the first read of `IOptions<PinotechrdSecurityOptions>.Value` (for example resolving `IPinotechrdAuthManager<TUser>` or the JWT bearer setup), so a `ServiceCollection` built by hand in tests fails too. Register an `IIdentityValidator<TUser>` that checks membership, or opt out with `PinotechrdSecurityOptions.AllowUnverifiedTenantMembership = true` when the application checks membership elsewhere. The opt-out is one value shared by every `AddPinotechrdSecurity` call, and binding `PinotechrdSecurityOptions` from configuration lets configuration turn the check off.
- **Users.** On a relational provider, `CreateUserAsync` throws `InvalidOperationException` when the context has pending changes. The Identity store saves every pending change of the shared context while creating the user, so a rollback of the user would silently lose them. Save or discard pending changes before calling it.
- **Permissions.** `AssignPermissionsToRoleAsync` no longer turns every exception into `false`: database and other unexpected errors now propagate. It still returns `false` for an invalid role id, an unknown role, or an invalid or unknown code. `ReplaceUserOverridesAsync` now returns `false` when the user does not exist. Both throw `InvalidOperationException` when the context has pending changes (save or discard them first) or its provider is not relational (they use a transaction, `ExecuteUpdate` and `ExecuteDelete`), so the EF Core in-memory provider is not supported. The no-op `UPDATE` that locks the role or user row fires `UPDATE` triggers and changes a row version (`xmin`, `rowversion`); an application that maps one as a concurrency token on users or roles must reload a tracked role or user after the call.
- **Model.** `role_permissions` has a unique index on (`RoleId`, `PermissionId`) and `user_permissions` one on (`UserId`, `PermissionId`), so a role holds a permission, and a user has an override for a permission, at most once. Applications must add a migration (`dotnet ef migrations add UniquePermissionAssignments`) and apply it to every tenant schema. Remove existing duplicate rows first, or the migration fails. Tenants provisioned with `GenerateCreateScript` instead of migrations need `CREATE UNIQUE INDEX "IX_role_permissions_RoleId_PermissionId" ON role_permissions ("RoleId", "PermissionId");` and `CREATE UNIQUE INDEX "IX_user_permissions_UserId_PermissionId" ON user_permissions ("UserId", "PermissionId");` in each tenant schema. See "Role permissions and user overrides" in the README for the SQL.
- **Search path.** In `TenantSchemaMode.SearchPath`, an exception from reading the connection's `ProcessID` now throws `InvalidOperationException` (the provider's exception as `InnerException`) instead of being swallowed. Before, it silently disabled the check that a command runs on the same database session that was bound to the tenant schema. When binding, the connection is closed and the open fails; on an already bound connection, the command is not sent. Providers without a `ProcessID` property are unaffected.
- **Cancellation.** Every public async method now takes a trailing `CancellationToken cancellationToken = default`: `IPinotechrdSecurityManager`, `IPinotechrdAuthManager`, `ISecurityDataProvider.GetUserRolesAsync`/`GetUserPermissionsAsync`, `ITenantStore.TenantExistsAsync`, `IIdentityValidator.ValidateAsync`, `IPinotechrdMessageService.SendCodeAsync`, `ISecurityStore`, `ISecurityEngine`, `SchemaManager` and `SecuritySeeder.SeedModuleAsync`, and their implementations. Callers recompile unchanged; **every application implementation of `ITenantStore`, `ISecurityDataProvider`, `IIdentityValidator`, `IPinotechrdMessageService` or `ISecurityStore` must add the parameter**, and NSubstitute stubs that use argument matchers need `Arg.Any<CancellationToken>()`. The token reaches EF Core, `IDistributedCache`, `IRefreshTokenStore`, `ITwoFactorAttemptStore` and the execution strategy; `UserManager` and `RoleManager` take no token, so it is checked before each Identity step. `TenantResolutionMiddleware` passes `HttpContext.RequestAborted` to `TenantExistsAsync`, and the permission handler passes it to `CanAccessAsync`. Once a security side effect starts, the rest runs to the end and ignores cancellation, which is checked only before it: revoking refresh tokens and then renewing the security stamp (`SignOutCurrentUserAsync`, `RevokeUserSessionsAsync`, deactivation in `SetUserActiveStatusAsync`) or deleting the user (`DeleteUserAsync`); consuming a refresh token in the EF store, including the reuse check and family revocation, so aborting a replayed token cannot dodge it; exhausting a two-factor challenge whose failure could not be recorded; committing the transaction of `CreateUserAsync`, `AssignPermissionsToRoleAsync` and `ReplaceUserOverridesAsync` once their work is done; rolling back to a savepoint; and, where no rollback exists (a non-relational provider, or a caller transaction without savepoints), assigning roles after `CreateUserAsync` created the user.
- **Schemas.** `SchemaManager.CreateSchemaAsync` accepts only `^[a-z_][a-z0-9_]{0,62}$` (lower case, at most 63 characters) and throws `ArgumentException` naming the rule otherwise. Before, it accepted upper case, which the lower-case search path check then rejected, and names longer than 63 bytes, which PostgreSQL truncates silently. Use `SchemaManager.CreateTenantSchemaAsync(tenantId)` to create the schema of a tenant from `TenantIdentifier.ToSchemaName`.

### Changed

- **Data Protection check.** `AddPinotechrdSecurity` registers a hosted service that, outside Development, logs a warning at startup (event id `4101`, `DataProtectionKeysNotPersisted`) when no Data Protection key repository is configured (`PersistKeysTo*`), because two-factor tokens then fail on another instance or after a restart. It needs `IHostEnvironment`, which every ASP.NET Core and generic host registers. Startup is not stopped.
- **Users.** `DeleteUserAsync` revokes the user's refresh tokens before deleting it. If revocation fails the user is not deleted; if the delete fails the tokens stay revoked. Access tokens stay valid until they expire.

### Fixed

- **Permissions.** `AssignPermissionsToRoleAsync` and `ReplaceUserOverridesAsync` deleted and re-inserted rows without a transaction, so concurrent calls for the same role or user failed with a concurrency error or left a mix of the requested sets. Each replace now runs in one transaction through the context's execution strategy: it locks the role or user row first (a no-op `UPDATE`), so replaces for the same role or user run one after the other, deletes with one `DELETE` and inserts the new rows. The requested permissions are checked again under the lock, so one deleted meanwhile returns `false`. A `DbUpdateException` from saving the new rows (a duplicate pair or a concurrency conflict) is retried up to five times; errors from the lock or the delete (a deadlock, a lock timeout) propagate unless the execution strategy treats them as transient. A failure leaves the previous assignments intact. Inside a transaction the caller opened, the replace runs once behind a savepoint and a failure rolls back to it; inside a `TransactionScope` it runs once and the scope owns atomicity.
- **Users.** `SetUserActiveStatusAsync(userId, false)` revoked nothing when `userId` was spelled differently from the stored id (for example in upper case), because it revoked under the caller's string. It now revokes under the user's stored id, as `DeleteUserAsync` does.
- **Stores.** `AddPinotechrdSecurity` adds the in-memory `IRefreshTokenStore` and `ITwoFactorAttemptStore` only when none is registered. Before, a store registered before `AddPinotechrdSecurity` was silently replaced by the in-memory default.
- **Users.** `CreateUserAsync` ignored the result of `AddToRolesAsync` and returned `true`, leaving a user without its roles. It now checks that every requested role exists before creating the user (an unknown or empty role name returns `false`), and on a relational provider creates the user and assigns its roles atomically: in a transaction of their own run through the context's execution strategy, or behind a savepoint inside a transaction the caller already opened, where the caller keeps the commit. Any failure rolls back and returns `false`. When a commit reports a transient error, a retrying strategy checks whether the user and its roles were stored and returns `true` if they were. The unit is not atomic on a non-relational provider or in a caller transaction on a provider without savepoints; inside a `TransactionScope` it is rolled back only if the caller abandons the scope.

## [1.2.0-preview.3] - 2026-11-18

### Removed (breaking)

- Tenant resolution no longer reads the JSON request body or the query string. `TenantResolutionOptions.JsonProperty` and `TenantResolutionOptions.QueryParameter` are gone. Reading the body buffered it with no size limit, and a query value ends up in logs and links. Send the tenant in the `TenantId` header (or the name set in `HeaderName`) on requests made before login.
- **Authorization.** A bare permission name no longer grants access. Before, `CanAccessAsync` also accepted the permission name alone, so a user holding `VIEW` had View in every module. Only the full `MODULE.PERMISSION` code grants it now. Roles, overrides or `ISecurityDataProvider` results that hold bare names must be rewritten to full codes; a policy without a dot (`Admin`) needs `GLOBAL.ADMIN`.

### Changed (breaking)

- **Tenant resolution.** For an authenticated user the verified claim is the only source: the header is never read, whatever `Sources` says. The claim is read from authenticated identities only, and two authenticated identities with different tenants are rejected with `tenant_invalid`. An authenticated user without the claim is rejected with `tenant_invalid` on a path that requires a tenant. `Sources` only decides whether unauthenticated requests may use the header.
- **Tenant resolution.** A request whose user is not authenticated when the middleware runs may use the header whatever other headers it carries, so a refresh request with an expired bearer token, or a login behind a gateway that adds `Authorization: Basic`, resolves its tenant normally.
- **Tenant resolution.** `UseTenantResolution()` adds a tenant consistency check to every endpoint the request runs. After authorization, and before the endpoint runs, any authenticated user must carry exactly one tenant claim equal to the resolved tenant; otherwise the response is `400` with code `tenant_invalid`.
  - This stops an endpoint that authenticates with its own scheme from running with a tenant named in the header.
  - It also rejects an authenticated user without a tenant claim on any endpoint that is not a skip path.
  - The check is installed through the request's endpoint feature, so it applies wherever `UseRouting()` sits in the pipeline, and to re-executed endpoints.
  - Not covered: code that calls `AuthenticateAsync` itself, and long-lived connections such as SignalR after they connect.
- **Tenant resolution.** `RequiredPathPrefix` and `SkipPaths` match whole path segments, ignoring case: `/api` no longer matches `/apix`, and `/health` no longer skips `/healthcheck`.
- **Tenant ids.** A tenant id must be 1 to 56 characters from `a-z`, `0-9` and `-`, not starting with `-` (`TenantIdentifier`). Other values are rejected as `tenant_invalid` without calling `ITenantStore`, and `TenantContext.SetTenant` throws `ArgumentException` for them. Upper-case ids are rejected, not folded.
- **Schemas.** `TenantContext.SchemaName` is `tenant_` plus the id with `-` replaced by `_`, a mapping that no longer merges different ids. `DbSchemaProvider.GetSchemaName` throws when no tenant is resolved instead of falling back to the shared `identity` schema; set `TenantResolutionOptions.UseSharedSchemaWhenNoTenant` to keep the fallback (for example for design-time tooling).
- **Database model.** `PinotechrdSecurityDbContext` refuses to build its model in the default `SchemaPerTenantInModel` mode unless the context options call `UsePinotechrdSecurity()` (or otherwise use `ModelSchemaCacheKeyFactory`). Before, the factory was never registered, so every context reused the first tenant's model and schema: a user of that tenant could log in naming another tenant and get a token for it. Add `.UsePinotechrdSecurity()` to `AddDbContext` and to any design-time factory.
- **Database model.** In `SchemaPerTenantInModel` mode the context throws in its constructor when a pre-built or compiled model is supplied (`UseModel`), because that model holds one tenant's schema and bypasses the per-schema cache.
- **Database model.** In `SearchPath` mode (PostgreSQL), `UsePinotechrdSecurity()` adds interceptors that bind every connection EF Core opens to the resolved tenant's schema. They also:
  - verify the binding, close the connection and throw on failure;
  - refuse to open without a tenant, or inside an ambient `TransactionScope`, where a rollback would restore the default path;
  - refuse every command on a connection that is not bound to the current tenant;
  - refuse, when the connection opens, connection strings with `Multiplexing`, `No Reset On Close`, `Search Path`, or `Options` that set `search_path`;
  - refuse, before it is sent, any EF Core command with a statement that changes `search_path`, `schema`, the role, the session authorization or `standard_conforming_strings` (`SET`, `RESET`, `RESET ALL`, `DISCARD ALL`, `ALTER ROLE|USER|DATABASE|SYSTEM ... SET|RESET`, `set_config` without a plain literal naming another setting, `U&"..."` identifiers), scanned the way PostgreSQL tokenises SQL, including `DO` and function bodies; column names such as `search_path` or `role` are not affected. This guards against mistakes in application SQL; it is not a security boundary and cannot see server-side functions, dynamic SQL assembled at run time or raw ADO.NET commands;
  - refuse any statement that writes to `pg_settings` (`UPDATE`, `INSERT INTO`, `DELETE FROM`, `MERGE INTO`, plain, `pg_catalog.`-qualified or quoted), which is equivalent to `SET`;
  - inside `DO` and function or procedure bodies, scan `EXECUTE` of one string literal (optionally parenthesised) and refuse any other `EXECUTE`, which cannot be checked;
  - refuse to bind a session whose `standard_conforming_strings` is off, read in the same round trip that verifies the path;
  - note: the interceptors do not re-read the path per command, so a change made by a server-side function the scanner cannot see persists on that connection until it closes (README, "SearchPath mode in detail");
  - forget the binding when the connection is closed or broken by anyone, and refuse a connection whose database session changed since it was bound;
  - refuse `UseSharedSchemaWhenNoTenant` (the context throws when it is created).

  PgBouncer in transaction or statement mode breaks the mode; use session pooling. Without the interceptors the context refuses to start, unless `ApplicationTakesResponsibilityForSearchPath` is set. SQLite and other providers cannot use `SearchPath` mode without that flag.
- **Database model.** The catalog table `subscription_plan_modules` no longer has a foreign key to the tenant table `security_modules`, and the navigations `SubscriptionPlanModule.Module` and `SecurityModule.PlanModules` are no longer mapped (they stay on the classes, always empty). The next migration drops that foreign key and adds an index on `"ModuleId"`.
- **Database model.** `ISchemaAwareContext.SchemaName` and `PinotechrdSecurityDbContext.SchemaName` are `string?`: `null` in `SearchPath` mode.
- **JWT.** `Issuer` and `Audience` are required and always validated. The secret must be at least 32 bytes in UTF-8; `MinimumSecretLength` counts bytes and cannot go below 32. Only HMAC-SHA256 is accepted when validating tokens.
- **JWT.** `AddPinotechrdSecurity` no longer throws for missing or weak JWT settings. They are validated when the host starts (`ValidateOnStart`), and the host fails with an `OptionsValidationException` naming each setting.
- **JWT.** The bearer validation settings the library guarantees are applied in a `PostConfigure` step, after every `Configure`, even when the application replaces `TokenValidationParameters`:
  - issuer, audience, lifetime and signing-key validation;
  - signed tokens with an expiry;
  - the configured issuer, audience and key;
  - HMAC-SHA256 only.

  Other application settings are kept.
- **Login.** `LoginAsync` returns `Invalid credentials` for a locked-out account too, instead of `Account locked out`, so the error does not tell which accounts exist. Lockout itself works as before.
- **Login.** `LoginAsync`, `VerifyTwoFactorCodeAsync` and `RefreshAsync` issue tokens only for the tenant resolved for the request (`TenantContext`). An unset tenant or a different `tenantId` is the generic failure. Before, the caller-supplied tenant went into the `tenant_id` claim unchecked.
- **Login.** Inactive users (`IsActive` false) can no longer log in, complete two-factor sign-in or refresh.
- **Two-factor.** `LoginAsync` now asks for the second factor when the user has two-factor enabled. Before, `CheckPasswordSignInAsync` never reported `RequiresTwoFactor`, so a password alone was enough.
- **Two-factor.** `AuthResult.TwoFactorToken` is now an opaque value protected with ASP.NET Core Data Protection, bound to the user, the tenant and the security stamp, and valid for five minutes. It used to be the user id, which anyone could send to `GetTwoFactorProvidersAsync`, `SendTwoFactorCodeAsync` and `VerifyTwoFactorCodeAsync`. A user id is no longer accepted by those methods.
- **Two-factor.** `VerifyTwoFactorCodeAsync`:
  - fails when `tenantId` is not the tenant the token was issued for;
  - allows five attempts per token;
  - counts a wrong code toward lockout, retrying concurrency conflicts after reloading the user (up to 10 times);
  - refuses locked-out users before and after checking the code;
  - rejects providers the user does not have.

  On success it renews the security stamp, which invalidates the token; a conflict is retried only while the stored stamp is still the token's. It then resets the failed count with retries, and fails if that cannot be recorded.
- **Two-factor.** `ITwoFactorAttemptStore` gains `ExhaustAsync`. A wrong code whose lockout count cannot be recorded spends the token's remaining attempts.
- **Two-factor.** `SendTwoFactorCodeAsync` refuses locked-out users and answers an unknown provider with a failure instead of an exception.
- **Refresh tokens.** `IRefreshTokenStore` gains `ConsumeAsync` (atomic validate and invalidate, with reuse detection by token family) and `RevokeAllForUserAsync`. `SaveAsync` gains `familyId` and `securityStamp`, and every method takes a `CancellationToken`. Existing implementations must add the new members. A default interface method could not make consumption atomic, so none is provided.
- **Refresh tokens.** `RefreshAsync` consumes the token atomically and refuses a token of another tenant without consuming it. It checks that the user:
  - exists and is active;
  - is not locked out and may sign in;
  - still has the security stamp it had when the token was issued;
  - passes `IIdentityValidator`.

  Every failure is `Invalid token`; neither the store's reason nor the validator's message is returned.
- **Refresh tokens.** `InMemoryRefreshTokenStore.SaveAsync` throws `InvalidOperationException` for a token value that is already stored, instead of overwriting its state. A consumed token presented again is `Reused` (and revokes its family) even when it has also expired or been revoked on its own; consumed tokens are kept until their whole family has expired, so a late replay is still detected.
- **Sign-out.** `SignOutAsync` revokes all refresh tokens of the user as well as renewing the security stamp. Access tokens stay valid until they expire.
- **Users.** `SetUserActiveStatusAsync(userId, false)` revokes the user's refresh tokens and renews its security stamp.
- **Login.** `LoginAsync`, `VerifyTwoFactorCodeAsync` and `RefreshAsync` write the tenant claim under `TenantResolutionOptions.ClaimType` (default `tenant_id`) instead of always `tenant_id`, so a custom claim type no longer makes every authenticated request answer `400 tenant_invalid`. `IOptions<PinotechrdSecurityOptions>.Value.Tenancy` now carries the configured tenancy settings. The configured claim type is exempt from the bearer handler's inbound claim mapping (only that type, on the library's bearer scheme, re-applied in `PostConfigure`), so a mapped name such as `tid` is no longer renamed and rejected; `GetPrincipalFromExpiredToken` reads it the same way. Other claims keep the default mapping.
- **Authorization.** `PermissionAuthorizationHandler` fails when the authenticated user's tenant claim is missing, two authenticated identities carry different tenants, no tenant is resolved, or claim and tenant differ. Without a `TenantContext` (constructed by hand) every requirement fails.
- **Authorization.** `SecurityEngine` trusts one tenant and denies, returning no permissions, when `ISecurityDataProvider.GetCurrentTenantId()` differs from it:
  - with an authenticated user in an HTTP request, the user's tenant claim, which must also equal `TenantContext`;
  - otherwise (anonymous requests, background work), `TenantContext`. Background work must call `TenantContext.SetTenant` before using the engine.
- **Authorization.** Module and permission codes are 1 to 100 characters from `A-Z a-z 0-9 _ . -`, compared after trimming and upper-casing everywhere. Other characters are rejected instead of folded (for example U+017F, which upper-cases to `S`):
  - `PermissionRequirement` throws `ArgumentException`;
  - the seeder throws;
  - `CanAccessAsync` and `IsModuleActiveAsync` return `false`;
  - `AssignPermissionsToRoleAsync` and `ReplaceUserOverridesAsync` return `false`.

  `PermissionRequirement.ModuleCode` and `Permission` are upper case, and the fallback module is `GLOBAL` instead of `Global`.
- **Authorization.** `AssignPermissionsToRoleAsync` returns `false` and changes nothing when a requested code is invalid or names a permission that does not exist. Before, such codes were dropped silently and the method returned `true`.
- `ResetPasswordAsync` answers an unknown e-mail with the same failure as an invalid reset token, instead of `User not found`.
- `PinotechrdAuthManager<TUser>` requires `TUser` to have a public parameterless constructor (`new()`). `AddPinotechrdSecurity` already required it.

### Migration

**Tenant identifiers.** Tenant ids must now match `TenantIdentifier.IsValid` (`a-z`, `0-9`, `-`; 1 to 56 characters; not starting with `-`).

- To keep a tenant's existing schema, pick the new id from the schema name: remove `tenant_`, keep it lower case, and turn `_` into `-`. The schema `tenant_acme_corp` belongs to the id `acme-corp`, which maps back to the same schema.
- Update the stored tenant identifier everywhere it is kept (the tenants table, `SystemSubscription.TenantName`, your `ITenantStore`, and any foreign data).
- Access tokens and refresh tokens issued with an old id stop working (the claim or the stored tenant no longer resolves); users must log in again.
- The old mapping (lower-casing and `-` to `_`) merged different ids into one schema, for example `a-b`, `a_b` and `A-B` all mapped to `tenant_a_b`. If you had such ids, they already shared a schema: decide which tenant owns it and move the other's data before renaming.

**Module ids.** `SecuritySeeder` now creates modules with `SecurityModuleId.FromCode(code)`, a UUIDv5 of the upper-case code, so the same module has the same id in every tenant schema and plans in the catalog can refer to it. Modules already seeded keep their random ids, and a plan mapping created for one tenant does not match the others. Until aligned, existing tenants only see plan modules whose ids happen to match. `SecuritySeeder` also sets each permission's module id, and fills it in for existing permissions that have none.

To align existing data on PostgreSQL, apply the database-model migration below first (it drops the old catalog-to-tenant foreign key), take a backup, list your tenant schemas in place of `{{SCHEMAS}}` (for example `ARRAY['tenant_acme','tenant_globex']`), and run this as one script. It rewrites module ids, permission module ids and catalog plan mappings in one transaction; `uuid_generate_v5` with this namespace equals `SecurityModuleId.FromCode`. Tested on PostgreSQL 17.7 with two tenants.

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA public;
BEGIN;
CREATE TEMP TABLE pinotechrd_module_id_map (old_id uuid PRIMARY KEY, new_id uuid NOT NULL) ON COMMIT DROP;
DO $$
DECLARE
  s  text;
  ns constant uuid := '4f8a2c1e-9d3b-4e7a-8c5f-2b6d1a9e7c30';
BEGIN
  FOREACH s IN ARRAY {{SCHEMAS}} LOOP
    EXECUTE format('INSERT INTO pinotechrd_module_id_map (old_id, new_id)
                    SELECT "Id", public.uuid_generate_v5(%L::uuid, upper(btrim("Code"))) FROM %I.security_modules
                    ON CONFLICT (old_id) DO NOTHING', ns, s);
    EXECUTE format('ALTER TABLE %I.security_permissions DROP CONSTRAINT "FK_security_permissions_security_modules_ModuleId"', s);
    EXECUTE format('UPDATE %I.security_permissions p SET "ModuleId" = m.new_id
                    FROM pinotechrd_module_id_map m WHERE p."ModuleId" = m.old_id', s);
    EXECUTE format('UPDATE %I.security_modules SET "Id" = public.uuid_generate_v5(%L::uuid, upper(btrim("Code")))', s, ns);
    EXECUTE format('ALTER TABLE %I.security_permissions ADD CONSTRAINT "FK_security_permissions_security_modules_ModuleId"
                    FOREIGN KEY ("ModuleId") REFERENCES %I.security_modules ("Id") ON DELETE CASCADE', s, s);
  END LOOP;
  UPDATE public.subscription_plan_modules spm SET "ModuleId" = m.new_id
  FROM pinotechrd_module_id_map m WHERE spm."ModuleId" = m.old_id;
END $$;
COMMIT;
```

Adjust the schema of the catalog table if `CatalogSchema` is not `public`, and the constraint name if your migrations named it differently.

**Database model.** Add `.UsePinotechrdSecurity()` to the security context options, then add a migration: it drops the foreign key from `subscription_plan_modules` to `security_modules`. In `SearchPath` mode with `ExcludeCatalogFromMigrations`, tenant migrations no longer contain the catalog tables; create those once, from a context with the catalog included.
### Added

- `TenantResolutionOptions.Sources`, `OnMissingTenant` (`MissingTenantBehavior.Reject` by default, or `Continue` so an anonymous caller of a protected endpoint gets `401`), `RequiredPathPrefix` (default `/api`, replaces the hard-coded prefix) and `UseSharedSchemaWhenNoTenant`.
- `TenantIdentifier` (`IsValid`, `ToSchemaName`, `MaxLength`, `SchemaPrefix`).
- Tenant rejections go through `IProblemDetailsService` when the application registers one, as `application/problem+json` with a `code` member (`tenant_required` or `tenant_invalid`, see `TenantResolutionErrorCodes`). Without it the plain-text body is unchanged.
- `UseTenantResolution()` throws `InvalidOperationException` when an authentication scheme is configured but `UseAuthentication()` has not run before it. Hosts without authentication are not affected.
- `ITwoFactorAttemptStore` and its default `InMemoryTwoFactorAttemptStore`, registered by `AddPinotechrdSecurity`.
- `RefreshTokenConsumeResult` and `RefreshTokenConsumeStatus`. `InMemoryRefreshTokenStore` and `InMemoryTwoFactorAttemptStore` accept a `TimeProvider`.
- `UsePinotechrdSecurity(Action<PinotechrdSecurityModelOptions>?)` on `DbContextOptionsBuilder`. Its settings:
  - `TenantSchemaMode`: `SchemaPerTenantInModel`, or `SearchPath`, where tenant tables have no schema in the model and the library binds `search_path`;
  - `CatalogSchema`: default `public`, `null` for `search_path`;
  - `ExcludeCatalogFromMigrations`;
  - `ApplicationTakesResponsibilityForSearchPath`.
- `SecurityModuleId.FromCode` and `SecurityModuleId.Namespace`: deterministic module ids.
- `TenantOutputCachePolicy` and `CacheOutputPerTenant()`: output caching keyed by the resolved tenant. Caching is turned off when tenant resolution or authorization has not run for the request (place `UseOutputCache()` after both), or when a path that requires a tenant has none. Response caching and caches in front of the application remain the operator's responsibility (README, "Caching").
- `PermissionAuthorizationHandler` takes optional `TenantContext` and `TenantResolutionOptions`; `SecurityEngine` takes optional `TenantContext`, `IHttpContextAccessor` and `TenantResolutionOptions`.
- `PinotechrdAuthManager<TUser>` takes optional `IDataProtectionProvider`, `TenantContext`, `ITwoFactorAttemptStore`, `TimeProvider` and `ISecurityDbContext` (used to reload the user on a concurrency conflict). Without a `TenantContext` every login and refresh fails; without a data protection provider or an attempt store, two-factor sign-in fails closed. `PinotechrdSecurityManager<TUser, TRole>` takes an optional `IRefreshTokenStore`.

### Security

- Login for an unknown or inactive user, a user without a password, a locked-out user, a user Identity does not allow to sign in, or a tenant mismatch verifies the password against a dummy hash, so the response time reveals less about which accounts exist. It is not constant time. The dummy hash is made once per password hasher type.
- An unknown, an inactive and a malformed tenant get the same status and body.
- An unknown tenant is rejected before any tenant-scoped context or model is built. In `SchemaPerTenantInModel` mode EF Core keeps a bounded number of models (measured at roughly 40 to 50); above about 40 active tenants use `SearchPath` mode.
- A bare permission name (for example `VIEW`) granted that permission in every module; only the full `MODULE.PERMISSION` code grants access now.
- The old tenant-id-to-schema mapping (lower-casing, `-` to `_`) merged different ids such as `a-b`, `a_b` and `A-B` into one schema, so those tenants shared data; ids are now restricted and the mapping is injective.
- A user authenticated only by an endpoint's own scheme ran with the tenant named in the header; every endpoint now checks the authenticated user's tenant claim against the resolved tenant.

## [1.2.0-preview.2] - 2026-11-17

### Changed (breaking)

- **Renamed** every public type and method from the `Pinotech` prefix to `Pinotechrd`, to match the package and namespace names:

  | Before | After |
  | --- | --- |
  | `AddPinotechSecurity` | `AddPinotechrdSecurity` |
  | `PinotechSecurityOptions` | `PinotechrdSecurityOptions` |
  | `PinotechSecurityDbContext<TUser, TRole>` | `PinotechrdSecurityDbContext<TUser, TRole>` |
  | `IPinotechAuthManager<TUser>` / `PinotechAuthManager<TUser>` | `IPinotechrdAuthManager<TUser>` / `PinotechrdAuthManager<TUser>` |
  | `IPinotechSecurityManager<TUser, TRole>` / `PinotechSecurityManager<TUser, TRole>` | `IPinotechrdSecurityManager<TUser, TRole>` / `PinotechrdSecurityManager<TUser, TRole>` |
  | `IPinotechMessageService` | `IPinotechrdMessageService` |

### Removed (breaking)

- `Tenant.NcfMode`, `Tenant.NcfPrefix`, `Tenant.DgiiApiKey`, `Tenant.DgiiApiUrl`, `Tenant.ConfigureNcf` and the `NcfMode` enum. Fiscal document settings are not a security concern; keep them in the host application. Applications that mapped these columns need a migration that moves or drops them.

### Added

- `GetActiveCatalogAsync` returns the modules on a tenant's active plan, each with its active permissions. A module outside the plan is absent.
- `GetUserOverridesAsync` and `ReplaceUserOverridesAsync` read and replace a user's Allow and Deny rows. An empty list clears them. Deny wins when both are sent for one code.
- The effective permission set is the role bundle, plus Allow, minus Deny. `CanAccessAsync` and `GetPermissionsAsync` use it. A full `Module.Permission` code matches only that module. A bare permission name still matches.

### Changed

- The plan catalog and the user overrides are not kept in the fifteen-minute security cache.

## [1.2.0-preview.1] - 2026-11-17

First release under the new name. Nothing was ever published to nuget.org under the old
names (`PinotechSecurity`, `Pinotech.Security.Abstractions`); they only existed as local packages.

### Changed (breaking)

- **Renamed** packages, assemblies and root namespaces:

  | Before | After |
  | --- | --- |
  | Package `PinotechSecurity` | `Pinotechrd.Security` |
  | Package `Pinotech.Security.Abstractions` | `Pinotechrd.Security.Abstractions` |
  | Namespace `Pinotech.Security.*` | `Pinotechrd.Security.*` |

  Public type and method names (`AddPinotechSecurity`, `PinotechSecurityOptions`,
  `IPinotechAuthManager`, ...) are unchanged.
- `Pinotechrd.Security` depends on `Pinotechrd.Security.Abstractions` with the same version.
- Microsoft.* dependencies updated from 10.0.6 to 10.0.15.

### Migration

1. Replace the package references:
   `PinotechSecurity` → `Pinotechrd.Security`, `Pinotech.Security.Abstractions` → `Pinotechrd.Security.Abstractions`, version `1.2.0-preview.1`.
2. Replace `using Pinotech.Security` with `using Pinotechrd.Security` (and any fully qualified `Pinotech.Security.` names).

### Build and release

- Repository reorganized into `src/`, `tests/` and `samples/`; solution is `Pinotechrd.Security.slnx`.
- Shared metadata in `Directory.Build.props`, package versions in `Directory.Packages.props` (Central Package Management), `global.json` and `.editorconfig` added.
- License declared as the `MIT` expression in both packages; README included in both.
- Source Link now comes from the .NET SDK; the explicit `Microsoft.SourceLink.GitHub` 8.0.0 reference
  (which pulled vulnerable `Microsoft.Build.Tasks.Git` 8.0.0, GHSA-23fw-v26w-5fgq) was removed.
- Library projects build with warnings as errors, track their public API with
  `Microsoft.CodeAnalysis.PublicApiAnalyzers` and enable package validation.
- Releases are published only from `v*` tags through nuget.org Trusted Publishing (no stored API key).
  Author signing with a certificate was removed; nuget.org repository-signs every uploaded package.

## [1.1.0] - 2026-07-21

### Added

- **Fase 2: hierarchical security engine.** `Core/SecurityEngine.cs` implements
  `ISecurityEngine` and evaluates access in three layers — Suscripción → Módulo
  → Permiso — via `ISecurityStore` (subscription + module state) and
  `ISecurityDataProvider` (user identity + permissions). Exposes:
  - `CanAccessAsync(moduleCode, permissionName)` for ad-hoc checks
  - `GetAuthorizedMenuAsync(fullMenu)` for the recursive filter used by the
    auth login response, with N+1-avoidance via `ToFrozenSet<string>` for the
    module + permission lookups
  - `GetPermissionsAsync(userId)` for the full permission set (filtered by
    active modules in the future if needed)
- **Fase 2.2: `Core/TenantCacheStore.cs`** decorator of `ISecurityStore` that
  adds an `IMemoryCache` layer (15-minute default expiration) around
  `IsSubscriptionActiveAsync`, `IsModuleActiveAsync`, and
  `GetActiveModuleCodesAsync`. Cache keys are scoped per tenant
  (`security:subscription:{tenantId}`, `security:module:{tenantId}:{moduleCode}`,
  `security:modules:codes:{tenantId}`) so multi-tenant blast radius is zero.
- **`Authorization/PermissionRequirement`** parses the `Module.Permission`
  format into `FullName`, `ModuleCode`, and `Permission` so ASP.NET Core
  authorization policies can express fine-grained requirements.
- **`Authorization/PermissionAuthorizationHandler`** evaluates the
  `PermissionRequirement` against the current user's `ISecurityEngine`
  results, so `[Authorize(Policy = "Orders.View")]` now respects the
  full Suscripción → Módulo → Permiso hierarchy.
- **`Extensions/AddPinotechSecurity()`** extension is now the single
  entry point that wires the engine, the cache decorator, and the
  authorization handler in the correct order. DI consumers no longer
  need to register each piece individually.

### Changed

- The `AddPinotechSecurity<TContext, TUser, TRole>` overload now requires
  the consumer to register an `ISecurityStore` implementation (or accept
  the default no-op store). The library no longer assumes the database
  layout — that decision is delegated to the consumer.
- `ISecurityDataProvider` contract is unchanged (an
  existing implementation keeps working).

### Upgrade Notes

- Consumers must register an `ISecurityStore`
  implementation that bridges their permission/subscription data to
  the new `IsSubscriptionActiveAsync` / `IsModuleActiveAsync` /
  `GetActiveModuleCodesAsync` contract. The library no longer auto-discovers
  the schema.
- Consumers that want cache-backed validation must register
  `services.AddMemoryCache()` before `AddPinotechSecurity()` (the
  handler is a decorator that requires `IMemoryCache` in DI).

## [1.0.0] - 2026-05-09

### Added

- Initial production-readiness baseline for coordinated NuGet publishing.
- CI workflow with test and packaging validation.
- Publish workflow for tag/manual release.
- Centralized package version policy via Directory.Build.props.
- Coverage gate enforcement in CI (`>= 70%`).
- Release hardening checks (version consistency and required changelog section).
- Rollback runbook for NuGet incidents.
- Executable sample API for package consumption.
- Public repository governance documents (`SECURITY.md`, `CONTRIBUTING.md`).
- Refresh token opaque lifecycle baseline (`IRefreshTokenStore`, in-memory implementation, rotation + revocation).
- NuGet vulnerability audit gates in CI and publish workflows (High/Critical fail policy).
- NuGet package signing and verification stage in publish workflow.
- Dependabot automation for NuGet and GitHub Actions dependencies.

### Changed

- Package messaging aligned to .NET 10 only.
- Abstractions package messaging aligned to Identity extension scenarios.
- NuGet metadata consistency improved for both packages.
- Tenant resolution now prioritizes authenticated claim source and no longer parses unsigned bearer payloads.
- Expired-token principal extraction now validates issuer/audience when configured.
- JWT secret policy enforces minimum length via startup and token provider guards.

### Security Advisory Notes

- Behavioral hardening: refresh tokens are validated server-side as opaque values and rotated on successful refresh.
- Behavioral hardening: weak JWT secrets now fail fast during service registration/startup.
- Behavioral hardening: tenant context must come from authenticated principal (fallback sources apply only when claim is unavailable).
- Consumer impact: systems relying on lax token/tenant behavior should validate startup config and refresh integration before rollout.
