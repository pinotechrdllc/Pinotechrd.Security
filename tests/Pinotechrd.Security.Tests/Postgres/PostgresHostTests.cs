using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Hosting;
using Pinotechrd.Security.Tests.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// The library's wiring end to end on PostgreSQL, in both schema modes: a real host (JWT bearer, tenant middleware, ASP.NET Identity,
/// in-memory refresh and two-factor stores) over a database whose two tenants are provisioned as the README documents.
/// The refresh store is the in-memory one: the library ships no database-backed refresh store, so refresh atomicity is proven by
/// the in-memory store tests, not here. Concurrency stamps (lockout, two-factor attempts) are proven here on a real database.
/// One host per mode is shared by the tests of the class; each test uses its own users.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresHostTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Alice = "alice@a.test";
    private const string Bob = "bob@b.test";

    private readonly Dictionary<TenantSchemaMode, (TenantDatabaseApi Api, ExecutionCounter Cookie, string ConnectionString)> _hosts = [];

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, "a", "b");
            var cookieCounter = new ExecutionCounter();
            var api = await TenantDatabaseApi.StartAsync(
                new Dictionary<string, string[]> { ["a"] = [Alice], ["b"] = [Bob] },
                mode,
                useDatabase: (options, _) => options.UseNpgsql(cs),
                provision: false,
                configureBuilder: builder =>
                {
                    builder.Services.AddSingleton(cookieCounter);
                    builder.Services.AddAuthentication().AddCookie("C", o =>
                    {
                        o.Cookie.Name = "c";
                        o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
                    });
                },
                mapExtra: app =>
                {
                    app.MapPost("/signin/{tenant}", async (string tenant, HttpContext http) =>
                    {
                        var identity = new ClaimsIdentity([new Claim("tenant_id", tenant), new Claim("sub", "cookie-user")], "C");
                        await http.SignInAsync("C", new ClaimsPrincipal(identity));
                        return Results.Ok();
                    });
                    app.MapGet("/api/cookie", (ExecutionCounter counter, TenantContext t) => { counter.Hit(); return Results.Text(t.TenantId ?? "none"); })
                        .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "C" });
                });
            _hosts[mode] = (api, cookieCounter, cs);
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var (api, _, _) in _hosts.Values) await api.DisposeAsync();
        Npgsql.NpgsqlConnection.ClearAllPools();
    }

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    public static IEnumerable<object[]> ModesAndCounts(int[] counts) =>
        PgProvisioning.Modes.SelectMany(mode => counts.Select(count => new object[] { mode, count }));

    public static IEnumerable<object[]> WrongCodeCounts() => ModesAndCounts([5, 10, 50]);

    public static IEnumerable<object[]> CorrectCodeCounts() => ModesAndCounts([2, 8, 32]);

    private TenantDatabaseApi Api(TenantSchemaMode mode) => _hosts[mode].Api;

    private static async Task<HttpStatusCode> RefreshAsync(TenantDatabaseApi api, string refresh, string tenant) =>
        (await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), tenant)).StatusCode;

    private static async Task<string> NextRefreshAsync(TenantDatabaseApi api, string refresh, string tenant)
    {
        var response = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), tenant);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("refresh").GetString()!;
    }

    // ---- Login -------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Login_ShouldSucceed_ForAUserOfTheTenantNamedInTheHeader(TenantSchemaMode mode)
    {
        var (access, refresh) = await Api(mode).LoginAsync(Alice, "a");

        access.Should().NotBeNullOrEmpty();
        refresh.Should().NotBeNullOrEmpty();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Login_ShouldBeRefused_WhenAUserOfTenantANamesTenantB_WithTheSameAnswerAsAnUnknownUser(TenantSchemaMode mode)
    {
        var api = Api(mode);

        var crossTenant = await api.PostAsync("/api/auth/login", new LoginRequest(Alice, TenantDatabaseApi.Password), "b");
        var unknown = await api.PostAsync("/api/auth/login", new LoginRequest("nobody@b.test", TenantDatabaseApi.Password), "b");

        crossTenant.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        unknown.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await crossTenant.Content.ReadAsStringAsync()).Should().Be(await unknown.Content.ReadAsStringAsync());
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Login_ShouldBeRefused_ForUnknownTenants_WithoutTouchingTheDatabase(TenantSchemaMode mode)
    {
        var response = await Api(mode).PostAsync("/api/auth/login", new LoginRequest(Alice, TenantDatabaseApi.Password), "zzz");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // ---- Refresh -----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Refresh_ShouldRotate_AndReuseOfAnOldTokenShouldRevokeTheFamily(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var (_, first) = await api.LoginAsync(Alice, "a");

        var second = await NextRefreshAsync(api, first, "a");
        var replay = await RefreshAsync(api, first, "a");
        var afterReplay = await RefreshAsync(api, second, "a");

        second.Should().NotBe(first);
        replay.Should().Be(HttpStatusCode.Unauthorized);
        afterReplay.Should().Be(HttpStatusCode.Unauthorized, "reusing a consumed token revokes the whole family");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Refresh_ShouldNotConsumeTheToken_WhenAnotherTenantPresentsIt(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var (_, refresh) = await api.LoginAsync(Alice, "a");

        var crossTenant = await RefreshAsync(api, refresh, "b");
        var owner = await RefreshAsync(api, refresh, "a");

        crossTenant.Should().Be(HttpStatusCode.Unauthorized);
        owner.Should().Be(HttpStatusCode.OK, "a cross-tenant attempt must not burn the owner's token");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SignOut_ShouldRevokeTheRefreshTokens(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var (access, refresh) = await api.LoginAsync(Alice, "a");

        var logout = await api.PostAsync("/api/auth/logout", new { }, "a", bearer: access);

        logout.StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await RefreshAsync(api, refresh, "a")).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Deactivating_ShouldBlockLoginAndRefresh(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var email = "gone-" + Guid.NewGuid().ToString("N")[..6] + "@a.test";
        await api.InTenantAsync("a", async sp =>
        {
            var created = await sp.GetRequiredService<UserManager<HostUser>>().CreateAsync(
                new HostUser { UserName = email, Email = email, EmailConfirmed = true }, TenantDatabaseApi.Password);
            created.Succeeded.Should().BeTrue();
            return 0;
        });
        var (_, refresh) = await api.LoginAsync(email, "a");

        await api.InTenantAsync("a", async sp =>
        {
            var user = await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(email);
            return await sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>().SetUserActiveStatusAsync(user!.Id.ToString(), false);
        });

        (await RefreshAsync(api, refresh, "a")).Should().Be(HttpStatusCode.Unauthorized);
        (await api.PostAsync("/api/auth/login", new LoginRequest(email, TenantDatabaseApi.Password), "a")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // ---- Tenant binding of authenticated requests --------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AuthenticatedRequest_ShouldStayInTenantA_WhenTheHeaderNamesTenantB(TenantSchemaMode mode)
    {
        var api = Api(mode);
        var (access, _) = await api.LoginAsync(Alice, "a");
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        request.Headers.Add("TenantId", "b");

        var response = await api.Client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("\"tenant\":\"a\"").And.Contain("\"claim\":\"a\"");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CookieUserOfTenantA_ShouldGet400AndNotRunTheEndpoint_WhenTheHeaderNamesTenantB(TenantSchemaMode mode)
    {
        var (api, counter, _) = _hosts[mode];
        // A separate client, so the cookie jar of the shared one stays clean.
        using var client = new HttpClient { BaseAddress = api.Client.BaseAddress };
        (await client.PostAsync("/signin/a", null)).StatusCode.Should().Be(HttpStatusCode.OK);
        var before = counter.Count;

        var mismatch = new HttpRequestMessage(HttpMethod.Get, "/api/cookie");
        mismatch.Headers.Add("TenantId", "b");
        var response = await client.SendAsync(mismatch);
        var match = new HttpRequestMessage(HttpMethod.Get, "/api/cookie");
        match.Headers.Add("TenantId", "a");
        var ok = await client.SendAsync(match);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync()).Should().Contain("tenant_invalid");
        counter.Count.Should().Be(before + 1, "only the matching request ran the endpoint");
        ok.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ---- Two-factor counting and single use on a real database -------------------------------

    private static async Task<(string Email, string Token)> NewTwoFactorUserAsync(TenantDatabaseApi api)
    {
        var email = "tf-" + Guid.NewGuid().ToString("N")[..8] + "@a.test";
        await api.InTenantAsync("a", async sp =>
        {
            var created = await sp.GetRequiredService<UserManager<HostUser>>().CreateAsync(
                new HostUser { UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = true }, TenantDatabaseApi.Password);
            created.Succeeded.Should().BeTrue();
            return 0;
        });
        return (email, await api.LoginForTwoFactorTokenAsync(email, "a"));
    }

    [Theory]
    [MemberData(nameof(WrongCodeCounts))]
    public async Task ParallelWrongCodes_ShouldLeaveTheAccountLockedOutAndNeverSucceed(TenantSchemaMode mode, int parallel)
    {
        var api = Api(mode);
        var (email, token) = await NewTwoFactorUserAsync(api);

        var results = await Task.WhenAll(Enumerable.Range(0, parallel).Select(_ => Task.Run(() =>
            api.InTenantAsync("a", sp => sp.GetRequiredService<IPinotechrdAuthManager<HostUser>>()
                .VerifyTwoFactorCodeAsync(token, "Email", "000000", "a")))));

        results.Should().AllSatisfy(r => r.Succeeded.Should().BeFalse());
        var lockedOut = await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            return await users.IsLockedOutAsync((await users.FindByEmailAsync(email))!);
        });
        lockedOut.Should().BeTrue($"{parallel} parallel wrong codes were counted against the account, whichever the mode");
    }

    [Theory]
    [MemberData(nameof(CorrectCodeCounts))]
    public async Task ParallelCorrectCodes_ShouldLetExactlyOneVerificationSucceed(TenantSchemaMode mode, int parallel)
    {
        var api = Api(mode);
        var (email, token) = await NewTwoFactorUserAsync(api);
        var code = await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            return await users.GenerateTwoFactorTokenAsync((await users.FindByEmailAsync(email))!, "Email");
        });

        var results = await Task.WhenAll(Enumerable.Range(0, parallel).Select(_ => Task.Run(() =>
            api.InTenantAsync("a", sp => sp.GetRequiredService<IPinotechrdAuthManager<HostUser>>()
                .VerifyTwoFactorCodeAsync(token, "Email", code, "a")))));

        results.Count(r => r.Succeeded).Should().Be(1, "a two-factor token is single use");
    }

    // ---- Where the rows went -----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task UsersCreatedThroughTheHost_ShouldBeInTheTenantSchemaTables(TenantSchemaMode mode)
    {
        var cs = _hosts[mode].ConnectionString;

        var inA = (long)(await PgProvisioning.ScalarAsync(cs, $"select count(*) from tenant_a.users where \"Email\" = '{Alice}'"))!;
        var inB = (long)(await PgProvisioning.ScalarAsync(cs, $"select count(*) from tenant_b.users where \"Email\" = '{Alice}'"))!;

        inA.Should().Be(1);
        inB.Should().Be(0);
    }
}
