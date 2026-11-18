using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// The README's "Seed and provision" flow (<c>ProvisionTenantAsync</c>), copied step by step, in both schema modes on PostgreSQL, behind
/// a host wired as the README's Quick Start wires it (catalog-backed tenant store, README data provider, schema provider from DI).
/// Run with the default tenant claim and with a custom claim type and header name, so a full round trip proves the configured tenancy
/// settings are what the tokens, the middleware and the permission handler use.
/// Difference from <see cref="PgProvisioning"/>: that helper is only step 1 of the README method (create the schema and run the
/// generated script, catalog with the first tenant); steps 2 and 3 (seed, role, user, plan, subscription, tenant row) exist only here.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresReadmeFlowTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Password = "Passw0rd!x";

    private sealed record Setup(InProcessHost Host, string ClaimType, string HeaderName, string ConnectionString);

    private readonly List<InProcessHost> _hosts = [];

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (var host in _hosts) await host.DisposeAsync();
        NpgsqlConnection.ClearAllPools();
    }

    // "tid" is one of the claim names the JWT handler renames on validation (to http://schemas.microsoft.com/identity/claims/tenantid):
    // it is the coordinator's own example of a custom name and it fails today (see the report); "tenant_ref" is a name the handler leaves alone.
    public static IEnumerable<object[]> Cases() =>
        PgProvisioning.Modes.SelectMany(mode => new[] { "tenant_id", "tenant_ref", "tid" }.Select(claim => new object[] { mode, claim }));

    // The README's AppTenantStore.
    private sealed class AppTenantStore(NpgsqlDataSource dataSource) : ITenantStore
    {
        public async Task<bool> TenantExistsAsync(string tenantId)
        {
            await using var command = dataSource.CreateCommand(
                "SELECT EXISTS (SELECT 1 FROM public.tenants WHERE \"Identifier\" = $1 AND \"Status\" = $2)");
            command.Parameters.Add(new NpgsqlParameter { Value = tenantId });
            command.Parameters.Add(new NpgsqlParameter { Value = (int)TenantStatus.Active });
            return (bool)(await command.ExecuteScalarAsync())!;
        }
    }

    // The README's AppSecurityDataProvider.
    private sealed class AppSecurityDataProvider(
        IHttpContextAccessor http, TenantContext tenant, IPinotechrdSecurityManager<HostUser, HostRole> security) : ISecurityDataProvider
    {
        public string? GetCurrentUserId() => http.HttpContext?.User.FindFirstValue("id");

        public string? GetCurrentTenantId() => tenant.TenantId;

        public Task<IEnumerable<string>> GetUserRolesAsync(string userId) => security.GetUserRolesAsync(userId);

        public async Task<IEnumerable<string>> GetUserPermissionsAsync(string userId)
        {
            var codes = new List<string>();
            foreach (var name in await security.GetUserRolesAsync(userId))
            {
                if (await security.GetRoleByNameAsync(name) is { } role)
                    codes.AddRange(await security.GetRolePermissionsAsync(role.Id.ToString()));
            }

            return codes;
        }
    }

    /// <summary>The README's ProvisionTenantAsync, with AppSecurityDbContext, AppUser and AppRole replaced by the test types.</summary>
    private static async Task ProvisionTenantAsync(IServiceProvider services, string connectionString, TenantSchemaMode mode,
        string tenantId, string customerName, string adminEmail, string adminPassword, bool createCatalog)
    {
        using var scope = services.CreateScope();
        var sp = scope.ServiceProvider;
        var tenant = sp.GetRequiredService<TenantContext>();
        tenant.SetTenant(tenantId);

        // 1. Schema and tables (the first tenant also creates the catalog tables).
        var tableOptions = new DbContextOptionsBuilder<SecDb>().UseNpgsql(connectionString);
        tableOptions.UsePinotechrdSecurity(model =>
        {
            model.TenantSchemaMode = mode;
            model.ExcludeCatalogFromMigrations = !createCatalog;
        });
        await using (var tables = new SecDb(tableOptions.Options, sp.GetRequiredService<ISchemaProvider>()))
        {
            var createSchema = $"CREATE SCHEMA IF NOT EXISTS \"{tenant.SchemaName}\"";
            await tables.Database.ExecuteSqlRawAsync(createSchema);
            await tables.Database.ExecuteSqlRawAsync(tables.Database.GenerateCreateScript());
        }

        // 2. Modules and permissions (full MODULE.PERMISSION codes), a role and its first user.
        await sp.GetRequiredService<SecuritySeeder>()
            .SeedModuleAsync("Sales", "SALES", null, 1, [("View sales", "SALES.VIEW", null)]);
        var security = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
        await security.CreateRoleAsync(new HostRole { Name = "seller" });
        var role = await security.GetRoleByNameAsync("seller");
        await security.AssignPermissionsToRoleAsync(role!.Id.ToString(), ["SALES.VIEW"]);
        await security.CreateUserAsync(new HostUser { UserName = adminEmail, Email = adminEmail }, adminPassword, ["seller"]);

        // 3. Catalog rows: a plan with the module, a started subscription for this tenant id, an active tenant.
        var db = sp.GetRequiredService<SecDb>();
        var plan = SubscriptionPlan.Create($"Basic {tenantId}", $"BASIC_{tenantId.ToUpperInvariant()}", null, 0m);
        db.SubscriptionPlans.Add(plan);
        db.SubscriptionPlanModules.Add(SubscriptionPlanModule.Create(plan.Id, SecurityModuleId.FromCode("SALES")));
        var subscription = SystemSubscription.Create(customerName, tenantId, plan.Id, DateOnly.FromDateTime(DateTime.UtcNow));
        db.SystemSubscriptions.Add(subscription);
        var row = Tenant.Create(subscription.Id, customerName, tenantId, tenant.SchemaName!);
        row.Status = TenantStatus.Active;
        db.Tenants.Add(row);
        await db.SaveChangesAsync();
    }

    private async Task<Setup> StartAsync(TenantSchemaMode mode, string claimType)
    {
        var cs = await postgres.CreateDatabaseAsync();
        var headerName = claimType == "tenant_id" ? "TenantId" : "X-Tenant";
        var host = await InProcessHost.StartAsync(
            builder =>
            {
                var services = builder.Services;
                services.AddProblemDetails();
                services.AddSingleton(NpgsqlDataSource.Create(cs));
                services.AddScoped<ISchemaProvider, DbSchemaProvider>();
                services.AddDbContext<SecDb>(options => options.UseNpgsql(cs).UsePinotechrdSecurity(model =>
                {
                    model.TenantSchemaMode = mode;
                    model.ExcludeCatalogFromMigrations = true;
                }));
                services.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(options =>
                {
                    options.Jwt.Secret = TenantDatabaseApi.Secret;
                    options.Jwt.Issuer = TenantDatabaseApi.Issuer;
                    options.Jwt.Audience = TenantDatabaseApi.Audience;
                    options.Tenancy.ClaimType = claimType;
                    options.Tenancy.HeaderName = headerName;
                });
                services.AddHttpContextAccessor();
                services.AddScoped<ITenantStore, AppTenantStore>();
                services.AddScoped<ISecurityDataProvider, AppSecurityDataProvider>();
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                app.UseAuthorization();

                app.MapPost("/api/auth/login", async (LoginRequest request, TenantContext tenant, IPinotechrdAuthManager<HostUser> auth) =>
                {
                    var result = await auth.LoginAsync(request.Email, request.Password, tenant.TenantId ?? string.Empty);
                    return result.Succeeded
                        ? Results.Json(new { access = result.Token!.AccessToken, refresh = result.Token.RefreshToken })
                        : Results.Json(new { error = result.ErrorMessage }, statusCode: 401);
                }).AllowAnonymous();
                app.MapPost("/api/auth/refresh", async (RefreshRequest request, IPinotechrdAuthManager<HostUser> auth) =>
                {
                    var result = await auth.RefreshAsync(request.RefreshToken);
                    return result.Succeeded
                        ? Results.Json(new { access = result.Token!.AccessToken, refresh = result.Token.RefreshToken })
                        : Results.Json(new { error = result.ErrorMessage }, statusCode: 401);
                }).AllowAnonymous();
                app.MapGet("/api/whoami", [Authorize] (HttpContext http, TenantContext tenant) => Results.Json(new { tenant = tenant.TenantId }));
                app.MapGet("/api/sales", [Authorize(Policy = "Sales.View")] () => Results.Ok("sales"));
                app.MapGet("/api/hr", [Authorize(Policy = "Hr.View")] () => Results.Ok("hr"));
            });
        _hosts.Add(host);

        await ProvisionTenantAsync(host.Services, cs, mode, "a", "A Corp", "admin@a.test", Password, createCatalog: true);
        await ProvisionTenantAsync(host.Services, cs, mode, "b", "B Corp", "admin@b.test", Password, createCatalog: false);
        return new Setup(host, claimType, headerName, cs);
    }

    private static HttpRequestMessage Request(Setup s, HttpMethod method, string path, string? tenant, string? bearer = null, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (tenant != null) request.Headers.Add(s.HeaderName, tenant);
        if (bearer != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body != null) request.Content = JsonContent.Create(body);
        return request;
    }

    private static async Task<(HttpStatusCode Status, string? Access, string? Refresh)> LoginAsync(Setup s, string email, string tenant)
    {
        var response = await s.Host.Client.SendAsync(Request(s, HttpMethod.Post, "/api/auth/login", tenant, body: new LoginRequest(email, Password)));
        if (response.StatusCode != HttpStatusCode.OK) return (response.StatusCode, null, null);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (response.StatusCode, json.RootElement.GetProperty("access").GetString(), json.RootElement.GetProperty("refresh").GetString());
    }

    // ---- The README flow ---------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ProvisionedTenant_ShouldLogIn_PassItsPermissionEndpoint_AndBeDeniedTheOne_ItLacks(TenantSchemaMode mode, string claimType)
    {
        var s = await StartAsync(mode, claimType);

        var (status, access, _) = await LoginAsync(s, "admin@a.test", "a");
        var sales = await s.Host.Client.SendAsync(Request(s, HttpMethod.Get, "/api/sales", "a", access));
        var hr = await s.Host.Client.SendAsync(Request(s, HttpMethod.Get, "/api/hr", "a", access));

        status.Should().Be(HttpStatusCode.OK);
        sales.StatusCode.Should().Be(HttpStatusCode.OK, "the role grants SALES.VIEW and the plan has SALES");
        hr.StatusCode.Should().Be(HttpStatusCode.Forbidden, "no HR permission exists for the user");
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ProvisionedTenant_ShouldRefuseALoginThatNamesTheOtherTenant_AndAcceptEachAdminInItsOwn(TenantSchemaMode mode, string claimType)
    {
        var s = await StartAsync(mode, claimType);

        (await LoginAsync(s, "admin@a.test", "b")).Status.Should().Be(HttpStatusCode.Unauthorized);
        (await LoginAsync(s, "admin@b.test", "a")).Status.Should().Be(HttpStatusCode.Unauthorized);
        (await LoginAsync(s, "admin@a.test", "a")).Status.Should().Be(HttpStatusCode.OK);
        var (status, access, _) = await LoginAsync(s, "admin@b.test", "b");
        status.Should().Be(HttpStatusCode.OK);
        (await s.Host.Client.SendAsync(Request(s, HttpMethod.Get, "/api/sales", "b", access))).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Tokens_ShouldCarryTheTenantUnderTheConfiguredClaimType_AndOnlyThere(TenantSchemaMode mode, string claimType)
    {
        var s = await StartAsync(mode, claimType);

        var (_, access, refresh) = await LoginAsync(s, "admin@a.test", "a");

        var claims = new JwtSecurityTokenHandler().ReadJwtToken(access).Claims.ToList();
        claims.Should().Contain(c => c.Type == claimType && c.Value == "a");
        if (claimType != "tenant_id") claims.Should().NotContain(c => c.Type == "tenant_id", "the tenant is issued under the configured claim name only");
        refresh.Should().NotBeNullOrEmpty();
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task FullRoundTrip_ShouldWork_WithTheConfiguredClaimTypeAndHeader(TenantSchemaMode mode, string claimType)
    {
        var s = await StartAsync(mode, claimType);
        var (_, access, refresh) = await LoginAsync(s, "admin@a.test", "a");

        // An authenticated request: the claim decides, the header naming the other tenant is ignored.
        var whoami = await s.Host.Client.SendAsync(Request(s, HttpMethod.Get, "/api/whoami", "b", access));
        var permission = await s.Host.Client.SendAsync(Request(s, HttpMethod.Get, "/api/sales", "a", access));
        // Refresh rotates the token and the new access token still carries the configured claim.
        var refreshed = await s.Host.Client.SendAsync(Request(s, HttpMethod.Post, "/api/auth/refresh", "a", body: new RefreshRequest(refresh!)));
        using var json = JsonDocument.Parse(await refreshed.Content.ReadAsStringAsync());
        var newAccess = json.RootElement.GetProperty("access").GetString()!;
        var again = await s.Host.Client.SendAsync(Request(s, HttpMethod.Get, "/api/sales", "a", newAccess));

        whoami.StatusCode.Should().Be(HttpStatusCode.OK);
        (await whoami.Content.ReadAsStringAsync()).Should().Contain("\"tenant\":\"a\"");
        permission.StatusCode.Should().Be(HttpStatusCode.OK);
        refreshed.StatusCode.Should().Be(HttpStatusCode.OK);
        new JwtSecurityTokenHandler().ReadJwtToken(newAccess).Claims.Should().Contain(c => c.Type == claimType && c.Value == "a");
        again.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Options_ShouldReflectTheConfiguredTenancySettings(TenantSchemaMode mode, string claimType)
    {
        var s = await StartAsync(mode, claimType);

        var options = s.Host.Services.GetRequiredService<IOptions<PinotechrdSecurityOptions>>().Value;
        var registered = s.Host.Services.GetRequiredService<TenantResolutionOptions>();

        options.Tenancy.ClaimType.Should().Be(claimType);
        options.Tenancy.HeaderName.Should().Be(s.HeaderName);
        options.Tenancy.ClaimType.Should().Be(registered.ClaimType);
        options.Tenancy.HeaderName.Should().Be(registered.HeaderName);
        options.Tenancy.RequiredPathPrefix.Should().Be("/api");
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task ATokenIssuedUnderAnotherClaimName_ShouldNotAuthenticateTheTenant(TenantSchemaMode mode, string claimType)
    {
        var s = await StartAsync(mode, claimType);
        var (_, access, _) = await LoginAsync(s, "admin@a.test", "a");
        // Re-sign the same claims under the other claim name: a token that does not carry the configured claim must be rejected.
        var original = new JwtSecurityTokenHandler().ReadJwtToken(access);
        var swappedType = claimType == "tid" ? "tenant_id" : "tid";
        var swapped = new JwtSecurityToken(
            TenantDatabaseApi.Issuer, TenantDatabaseApi.Audience,
            original.Claims.Select(c => c.Type == claimType ? new Claim(swappedType, c.Value) : c),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(TenantDatabaseApi.Secret)),
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256));

        var response = await s.Host.Client.SendAsync(Request(s, HttpMethod.Get, "/api/sales", "a", new JwtSecurityTokenHandler().WriteToken(swapped)));

        response.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Forbidden, HttpStatusCode.Unauthorized);
        response.StatusCode.Should().NotBe(HttpStatusCode.OK);
    }
}
