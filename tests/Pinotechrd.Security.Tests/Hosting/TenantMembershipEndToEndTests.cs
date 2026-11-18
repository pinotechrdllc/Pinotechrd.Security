using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// Membership, as the README describes it: the user is looked up in the tenant's own tables, so finding the user is what
/// proves membership. Proven here with one SQLite database per tenant through the library's own wiring. The PostgreSQL schema modes
/// (schema in the model and <c>search_path</c>) are proven against a real server in <c>PostgresHostTests</c>.
/// </summary>
public class TenantMembershipEndToEndTests
{
    /// <summary>Records the schema of every context that asks the model cache for its model.</summary>
    public sealed class CountingModelCacheKeyFactory : ModelSchemaCacheKeyFactory, IModelCacheKeyFactory
    {
        public static ConcurrentQueue<string?> Schemas { get; } = new();

        object IModelCacheKeyFactory.Create(DbContext context, bool designTime)
        {
            Schemas.Enqueue((context as ISchemaAwareContext)?.SchemaName);
            return Create(context, designTime);
        }
    }

    private const string AliceEmail = "alice@a.test";
    private const string BobEmail = "bob@b.test";

    private static readonly IReadOnlyDictionary<string, string[]> Users = new Dictionary<string, string[]>
    {
        ["tenant-a"] = [AliceEmail],
        ["tenant-b"] = [BobEmail]
    };

    private static async Task<string> ReadAsync(HttpResponseMessage response) => await response.Content.ReadAsStringAsync();

    // ---- Login -------------------------------------------------------------------------------

    [Fact]
    public async Task Login_ShouldSucceed_ForAUserOfTheTenantNamedInTheHeader()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);

        var (access, refresh) = await api.LoginAsync(AliceEmail, "tenant-a");

        access.Should().NotBeNullOrEmpty();
        refresh.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Login_ShouldFail_WhenAUserOfTenantANamesTenantB()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);

        var response = await api.PostAsync("/api/auth/login", new LoginRequest(AliceEmail, TenantDatabaseApi.Password), "tenant-b");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await ReadAsync(response)).Should().Contain("Invalid credentials");
    }

    [Fact]
    public async Task Login_ShouldGiveTheSameAnswer_WhenAUserOfAnotherTenantNamesThisOne_AsForAnUnknownUser()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);

        var wrongTenant = await api.PostAsync("/api/auth/login", new LoginRequest(AliceEmail, TenantDatabaseApi.Password), "tenant-b");
        var unknown = await api.PostAsync("/api/auth/login", new LoginRequest("nobody@b.test", TenantDatabaseApi.Password), "tenant-b");

        wrongTenant.StatusCode.Should().Be(unknown.StatusCode);
        (await ReadAsync(wrongTenant)).Should().Be(await ReadAsync(unknown));
    }

    [Fact]
    public async Task Login_ShouldFail_WhenAUserOfTenantBNamesTenantA()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);

        var response = await api.PostAsync("/api/auth/login", new LoginRequest(BobEmail, TenantDatabaseApi.Password), "tenant-a");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task EachTenant_ShouldFindOnlyItsOwnUsers_AndHaveItsOwnModel()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);

        var aSeesAlice = await api.InTenantAsync("tenant-a", async sp => await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(AliceEmail) != null);
        var aSeesBob = await api.InTenantAsync("tenant-a", async sp => await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(BobEmail) != null);
        var bSeesBob = await api.InTenantAsync("tenant-b", async sp => await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(BobEmail) != null);
        var bSeesAlice = await api.InTenantAsync("tenant-b", async sp => await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(AliceEmail) != null);
        var modelA = await api.InTenantAsync("tenant-a", sp => Task.FromResult<object>(sp.GetRequiredService<SecDb>().Model));
        var modelB = await api.InTenantAsync("tenant-b", sp => Task.FromResult<object>(sp.GetRequiredService<SecDb>().Model));

        aSeesAlice.Should().BeTrue();
        aSeesBob.Should().BeFalse();
        bSeesBob.Should().BeTrue();
        bSeesAlice.Should().BeFalse();
        modelA.Should().NotBeSameAs(modelB);
    }

    // ---- Refresh -----------------------------------------------------------------------------

    [Fact]
    public async Task Refresh_ShouldFailUnderTenantB_AndNotConsumeTheTokenOfTenantA()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        var (_, refresh) = await api.LoginAsync(AliceEmail, "tenant-a");

        var underB = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "tenant-b");
        var underA = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "tenant-a");

        underB.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await ReadAsync(underB)).Should().Contain("Invalid token");
        underA.StatusCode.Should().Be(HttpStatusCode.OK, "the cross-tenant attempt did not burn the token");
    }

    [Fact]
    public async Task Refresh_ShouldRotateWithinTheTenant_AndKeepTheTenantClaim()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        var (_, refresh) = await api.LoginAsync(AliceEmail, "tenant-a");

        var refreshed = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "tenant-a");
        using var json = JsonDocument.Parse(await ReadAsync(refreshed));
        var me = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        me.Headers.Authorization = new AuthenticationHeaderValue("Bearer", json.RootElement.GetProperty("access").GetString());
        var meResponse = await api.Client.SendAsync(me);

        refreshed.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadAsync(meResponse)).Should().Contain("\"claim\":\"tenant-a\"");
    }

    // ---- A token stays in its tenant ---------------------------------------------------------

    [Fact]
    public async Task TokenOfTenantA_ShouldStayInTenantA_WhenTheHeaderNamesTenantB()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        var (access, _) = await api.LoginAsync(AliceEmail, "tenant-a");

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        request.Headers.Add("TenantId", "tenant-b");
        var response = await api.Client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadAsync(response);
        body.Should().Contain("\"tenant\":\"tenant-a\"").And.Contain("\"claim\":\"tenant-a\"");
    }

    // ---- Probe: a single-page app sends the expired access token together with the refresh request ----

    [Fact]
    public async Task Probe_RefreshWithAnExpiredAccessTokenInAuthorization_ShouldSucceedAndRotateTheToken()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        var (_, refresh) = await api.LoginAsync(AliceEmail, "tenant-a");
        var expired = TenantDatabaseApi.ExpiredAccessToken("tenant-a", TimeSpan.FromMinutes(30));

        var withExpired = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "tenant-a", bearer: expired);
        var replay = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "tenant-a");

        // The expired token authenticates nobody, so the tenant header names the tenant, as for any anonymous request.
        withExpired.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = JsonDocument.Parse(await ReadAsync(withExpired));
        var rotated = json.RootElement.GetProperty("refresh").GetString();
        rotated.Should().NotBeNullOrEmpty().And.NotBe(refresh);
        // The old token was consumed by that refresh: using it again is a reuse and fails generically.
        replay.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await ReadAsync(replay)).Should().Contain("Invalid token");
    }

    [Fact]
    public async Task Probe_RefreshWithAStillValidAccessToken_ShouldWork_BecauseTheTenantComesFromItsClaim()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        var (access, refresh) = await api.LoginAsync(AliceEmail, "tenant-a");

        var response = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), tenant: null, bearer: access);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("YWxpY2U6cGFzcw==")]
    public async Task Probe_RefreshWithAForeignOrMalformedAuthorizationHeader_ShouldSucceed(string credentials)
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        var (_, refresh) = await api.LoginAsync(AliceEmail, "tenant-a");
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/refresh") { Content = System.Net.Http.Json.JsonContent.Create(new RefreshRequest(refresh)) };
        request.Headers.Add("TenantId", "tenant-a");
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var response = await api.Client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Probe_LoginWithAStaleAuthorizationHeader_ShouldSucceed()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        var expired = TenantDatabaseApi.ExpiredAccessToken("tenant-a", TimeSpan.FromMinutes(30));

        var response = await api.PostAsync("/api/auth/login", new LoginRequest(AliceEmail, TenantDatabaseApi.Password), "tenant-a", bearer: expired);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Probe_RefreshWithAnAccessTokenOfAnotherTenant_ShouldNotConsumeTheToken()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        var (_, aliceRefresh) = await api.LoginAsync(AliceEmail, "tenant-a");
        var (bobAccess, _) = await api.LoginAsync(BobEmail, "tenant-b");

        var response = await api.PostAsync("/api/auth/refresh", new RefreshRequest(aliceRefresh), "tenant-a", bearer: bobAccess);
        var retry = await api.PostAsync("/api/auth/refresh", new RefreshRequest(aliceRefresh), "tenant-a");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the access token puts the request in tenant B");
        retry.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ---- Two-factor counting on a real EF store ---------------------------------------------

    [Fact]
    public async Task FiveParallelWrongCodes_ShouldLeaveTheAccountLockedOut_OnARealEntityFrameworkStore()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);

        for (var round = 0; round < 4; round++)
        {
            var email = $"carol{round}@a.test";
            await api.InTenantAsync("tenant-a", async sp =>
            {
                var created = await sp.GetRequiredService<UserManager<HostUser>>().CreateAsync(
                    new HostUser { UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = true },
                    TenantDatabaseApi.Password);
                created.Succeeded.Should().BeTrue();
                return 0;
            });
            var twoFactorToken = await api.LoginForTwoFactorTokenAsync(email, "tenant-a");

            var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => Task.Run(() =>
                api.InTenantAsync("tenant-a", sp => sp.GetRequiredService<IPinotechrdAuthManager<HostUser>>()
                    .VerifyTwoFactorCodeAsync(twoFactorToken, "Email", "000000", "tenant-a")))));

            results.Should().AllSatisfy(r => r.Succeeded.Should().BeFalse());
            var lockedOut = await api.InTenantAsync("tenant-a", async sp =>
            {
                var users = sp.GetRequiredService<UserManager<HostUser>>();
                return await users.IsLockedOutAsync((await users.FindByEmailAsync(email))!);
            });
            lockedOut.Should().BeTrue($"round {round}: five wrong codes were all counted, so the lockout threshold was reached");
        }
    }

    [Fact]
    public async Task ASixthCode_ShouldBeRefused_AfterFiveParallelWrongOnes_EvenIfItIsCorrect()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);
        const string email = "dave@a.test";
        await api.InTenantAsync("tenant-a", async sp =>
        {
            await sp.GetRequiredService<UserManager<HostUser>>().CreateAsync(
                new HostUser { UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = true },
                TenantDatabaseApi.Password);
            return 0;
        });
        var twoFactorToken = await api.LoginForTwoFactorTokenAsync(email, "tenant-a");
        await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => Task.Run(() =>
            api.InTenantAsync("tenant-a", sp => sp.GetRequiredService<IPinotechrdAuthManager<HostUser>>()
                .VerifyTwoFactorCodeAsync(twoFactorToken, "Email", "000000", "tenant-a")))));

        var code = await api.InTenantAsync("tenant-a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            return await users.GenerateTwoFactorTokenAsync((await users.FindByEmailAsync(email))!, "Email");
        });
        var result = await api.InTenantAsync("tenant-a", sp => sp.GetRequiredService<IPinotechrdAuthManager<HostUser>>()
            .VerifyTwoFactorCodeAsync(twoFactorToken, "Email", code, "tenant-a"));

        result.Succeeded.Should().BeFalse();
    }

    // ---- Unknown tenants never reach the database layer --------------------------------------

    [Fact]
    public async Task TwoHundredLoginsNamingUnknownTenants_ShouldAnswerTenantInvalid_AndBuildNoPerTenantModel()
    {
        await using var api = await TenantDatabaseApi.StartAsync(
            Users,
            configureOptions: options => options.ReplaceService<IModelCacheKeyFactory, CountingModelCacheKeyFactory>());
        CountingModelCacheKeyFactory.Schemas.Clear();

        for (var i = 0; i < 200; i++)
        {
            var response = await api.PostAsync(
                "/api/auth/login", new LoginRequest(AliceEmail, TenantDatabaseApi.Password), $"unknown-{i}");

            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
            (await ReadAsync(response)).Should().Contain("\"code\":\"tenant_invalid\"");
        }

        CountingModelCacheKeyFactory.Schemas.Should().BeEmpty("no context, and so no model, was created for an unknown tenant");

        // Control: a known tenant does create its own model through the same factory.
        await api.LoginAsync(AliceEmail, "tenant-a");
        CountingModelCacheKeyFactory.Schemas.Should().Contain("tenant_tenant_a");
        CountingModelCacheKeyFactory.Schemas.Where(s => s != null && s.Contains("unknown")).Should().BeEmpty();
    }

    // ---- Two correct verifications of one token ----------------------------------------------

    [Fact]
    public async Task TwoParallelCorrectCodes_ShouldLetExactlyOneVerificationSucceed_OnARealEntityFrameworkStore()
    {
        await using var api = await TenantDatabaseApi.StartAsync(Users);

        for (var round = 0; round < 4; round++)
        {
            var email = $"erin{round}@a.test";
            await api.InTenantAsync("tenant-a", async sp =>
            {
                await sp.GetRequiredService<UserManager<HostUser>>().CreateAsync(
                    new HostUser { UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = true },
                    TenantDatabaseApi.Password);
                return 0;
            });
            var token = await api.LoginForTwoFactorTokenAsync(email, "tenant-a");
            var code = await api.InTenantAsync("tenant-a", async sp =>
            {
                var users = sp.GetRequiredService<UserManager<HostUser>>();
                return await users.GenerateTwoFactorTokenAsync((await users.FindByEmailAsync(email))!, "Email");
            });

            var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => Task.Run(() =>
                api.InTenantAsync("tenant-a", sp => sp.GetRequiredService<IPinotechrdAuthManager<HostUser>>()
                    .VerifyTwoFactorCodeAsync(token, "Email", code, "tenant-a")))));

            results.Count(r => r.Succeeded).Should().Be(1, $"round {round}: a token is single use");
        }
    }
}
