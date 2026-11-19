using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// Login, refresh rotation, reuse detection, sign-out and tenant binding through a real pipeline:
/// the library's own AddPinotechrdSecurity wiring, ASP.NET Identity over the EF Core in-memory store,
/// the in-memory refresh token store, and the real JWT bearer handler.
/// </summary>
public class EndToEndTests
{
    private const string Email = "alice@x.test";
    private const string Password = "Passw0rd!x";

    private sealed record LoginRequest(string Email, string Password);

    private sealed record RefreshRequest(string RefreshToken);

    private static async Task<InProcessHost> StartAsync()
    {
        var host = await InProcessHost.StartAsync(
            builder =>
            {
                var databaseName = Guid.NewGuid().ToString();
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = "end-to-end-secret-key-with-more-than-32-bytes";
                    o.Jwt.Issuer = "e2e";
                    o.Jwt.Audience = "e2e-clients";
                    o.AllowUnverifiedTenantMembership = true;
                });
                builder.Services.AddHostStubs();
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                app.UseAuthorization();

                app.MapPost("/api/auth/login", async (LoginRequest request, TenantContext tenant, IPinotechrdAuthManager<HostUser> auth) =>
                {
                    var result = await auth.LoginAsync(request.Email, request.Password, tenant.TenantId!);
                    return result.Succeeded
                        ? Results.Json(new { access = result.Token!.AccessToken, refresh = result.Token.RefreshToken })
                        : Results.Json(new { error = result.ErrorMessage }, statusCode: 401);
                });

                app.MapPost("/api/auth/refresh", async (RefreshRequest request, IPinotechrdAuthManager<HostUser> auth) =>
                {
                    var result = await auth.RefreshAsync(request.RefreshToken);
                    return result.Succeeded
                        ? Results.Json(new { access = result.Token!.AccessToken, refresh = result.Token.RefreshToken })
                        : Results.Json(new { error = result.ErrorMessage }, statusCode: 401);
                });

                app.MapPost("/api/auth/logout", [Authorize] async (HttpContext http, IPinotechrdAuthManager<HostUser> auth) =>
                {
                    await auth.SignOutAsync(http.User.FindFirst("id")!.Value);
                    return Results.NoContent();
                });

                app.MapGet("/api/me", [Authorize] (HttpContext http, TenantContext tenant) => Results.Json(new
                {
                    tenant = tenant.TenantId,
                    claim = http.User.FindFirst("tenant_id")?.Value
                }));
            });

        using var scope = host.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<HostUser>>();
        var created = await users.CreateAsync(new HostUser { UserName = "alice", Email = Email }, Password);
        created.Succeeded.Should().BeTrue(string.Join(", ", created.Errors.Select(e => e.Description)));
        return host;
    }

    private static async Task<HttpResponseMessage> PostAsync(InProcessHost host, string path, object body, string? tenant, string? bearer = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        if (tenant != null) request.Headers.Add("TenantId", tenant);
        if (bearer != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await host.Client.SendAsync(request);
    }

    private static async Task<(string Access, string Refresh)> LoginAsync(InProcessHost host, string tenant = "tenant-a")
    {
        var response = await PostAsync(host, "/api/auth/login", new LoginRequest(Email, Password), tenant);
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (json.RootElement.GetProperty("access").GetString()!, json.RootElement.GetProperty("refresh").GetString()!);
    }

    private static async Task<(HttpStatusCode Status, string? Refresh)> RefreshAsync(InProcessHost host, string refresh, string? tenant = "tenant-a")
    {
        var response = await PostAsync(host, "/api/auth/refresh", new RefreshRequest(refresh), tenant);
        if (response.StatusCode != HttpStatusCode.OK) return (response.StatusCode, null);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (response.StatusCode, json.RootElement.GetProperty("refresh").GetString());
    }

    [Fact]
    public async Task Login_ShouldIssueTokensWhoseClaimCarriesTheHeaderTenant()
    {
        await using var host = await StartAsync();
        var (access, _) = await LoginAsync(host, "tenant-b");

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        var me = await host.Client.SendAsync(request);

        me.StatusCode.Should().Be(HttpStatusCode.OK);
        (await me.Content.ReadAsStringAsync()).Should().Contain("\"claim\":\"tenant-b\"");
    }

    [Fact]
    public async Task Login_ShouldReturnTheSameFailure_ForAWrongPasswordAndAnUnknownUser()
    {
        await using var host = await StartAsync();

        var wrong = await PostAsync(host, "/api/auth/login", new LoginRequest(Email, "Wrong-Passw0rd"), "tenant-a");
        var unknown = await PostAsync(host, "/api/auth/login", new LoginRequest("nobody@x.test", "Wrong-Passw0rd"), "tenant-a");

        wrong.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        unknown.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await wrong.Content.ReadAsStringAsync()).Should().Be(await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Login_ShouldBeRejectedAsTenantRequired_WhenThereIsNoTenantHeader()
    {
        await using var host = await StartAsync();

        var response = await PostAsync(host, "/api/auth/login", new LoginRequest(Email, Password), tenant: null);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Login_ShouldBeRejected_WhenTheTenantInTheBodyOrQueryIsTheOnlyOneGiven()
    {
        await using var host = await StartAsync();

        var response = await host.Client.PostAsync(
            "/api/auth/login?tenantId=tenant-a",
            JsonContent.Create(new { email = Email, password = Password, tenantId = "tenant-a" }));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Refresh_ShouldRotateTheToken_AndRejectTheOldOneAndRevokeTheFamily_WhenReused()
    {
        await using var host = await StartAsync();
        var (_, first) = await LoginAsync(host);

        var second = await RefreshAsync(host, first);
        var replay = await RefreshAsync(host, first);
        var afterReplay = await RefreshAsync(host, second.Refresh!);

        second.Status.Should().Be(HttpStatusCode.OK);
        second.Refresh.Should().NotBe(first);
        replay.Status.Should().Be(HttpStatusCode.Unauthorized);
        afterReplay.Status.Should().Be(HttpStatusCode.Unauthorized, "reusing a consumed token revokes the whole family");
    }

    [Fact]
    public async Task Refresh_ShouldKeepRotating_WhenEachTokenIsUsedOnce()
    {
        await using var host = await StartAsync();
        var (_, token) = await LoginAsync(host);

        for (var i = 0; i < 3; i++)
        {
            var next = await RefreshAsync(host, token);
            next.Status.Should().Be(HttpStatusCode.OK);
            token = next.Refresh!;
        }
    }

    [Fact]
    public async Task Refresh_ShouldNotConsumeTheToken_WhenAnotherTenantPresentsIt()
    {
        await using var host = await StartAsync();
        var (_, refresh) = await LoginAsync(host, "tenant-a");

        var crossTenant = await RefreshAsync(host, refresh, "tenant-b");
        var owner = await RefreshAsync(host, refresh, "tenant-a");

        crossTenant.Status.Should().Be(HttpStatusCode.Unauthorized);
        owner.Status.Should().Be(HttpStatusCode.OK, "a cross-tenant attempt must not burn the owner's token");
    }

    [Fact]
    public async Task Refresh_ShouldFail_WhenNoTenantHeaderIsSent()
    {
        await using var host = await StartAsync();
        var (_, refresh) = await LoginAsync(host);

        var result = await RefreshAsync(host, refresh, tenant: null);

        result.Status.Should().Be(HttpStatusCode.BadRequest);
        (await RefreshAsync(host, refresh)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AuthenticatedRequest_ShouldStayInItsOwnTenant_WhenTheHeaderNamesAnotherTenant()
    {
        await using var host = await StartAsync();
        var (access, _) = await LoginAsync(host, "tenant-a");

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        request.Headers.Add("TenantId", "tenant-b");
        var response = await host.Client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("\"tenant\":\"tenant-a\"").And.Contain("\"claim\":\"tenant-a\"");
    }

    [Fact]
    public async Task SignOut_ShouldRevokeTheRefreshTokens_SoARefreshAfterwardsFails()
    {
        await using var host = await StartAsync();
        var (access, refresh) = await LoginAsync(host);

        var logout = await PostAsync(host, "/api/auth/logout", new { }, "tenant-a", bearer: access);
        var result = await RefreshAsync(host, refresh);

        logout.StatusCode.Should().Be(HttpStatusCode.NoContent);
        result.Status.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Deactivating_ShouldBlockLoginAndRefresh()
    {
        await using var host = await StartAsync();
        var (_, refresh) = await LoginAsync(host);
        using (var scope = host.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<HostUser>>();
            var manager = scope.ServiceProvider.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            var user = await users.FindByEmailAsync(Email);
            (await manager.SetUserActiveStatusAsync(user!.Id.ToString(), false)).Should().BeTrue();
        }

        var refreshed = await RefreshAsync(host, refresh);
        var login = await PostAsync(host, "/api/auth/login", new LoginRequest(Email, Password), "tenant-a");

        refreshed.Status.Should().Be(HttpStatusCode.Unauthorized);
        login.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
