using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace MultiNodeTests;

/// <summary>
/// The library across two nodes: separate processes in Production that share only what real nodes share (PostgreSQL
/// through PgBouncer in session mode with a role per tenant, Redis, the Data Protection key folder, the signing secret).
/// Each scenario starts on one node and checks the effect on the other. Started by run.ps1.
/// </summary>
public class MultiNodeScenarios
{
    private const string Password = "Multinode-Passw0rd!";

    private static readonly HttpClient Node1 = new() { BaseAddress = new Uri(Environment.GetEnvironmentVariable("NODE1") ?? "http://localhost:5101") };
    private static readonly HttpClient Node2 = new() { BaseAddress = new Uri(Environment.GetEnvironmentVariable("NODE2") ?? "http://localhost:5102") };

    private static HttpRequestMessage Request(HttpMethod method, string path, string tenant, string? bearer = null, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("TenantId", tenant);
        if (bearer != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (body != null) request.Content = JsonContent.Create(body);
        return request;
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.Clone();
    }

    private static async Task<(string Access, string Refresh)> LoginAsync(HttpClient node, string tenant, string email)
    {
        var response = await node.SendAsync(Request(HttpMethod.Post, "/api/auth/login", tenant, body: new { email, password = Password }));
        response.StatusCode.Should().Be(HttpStatusCode.OK, $"{email} signs in to {tenant}");
        var json = await JsonAsync(response);
        return (json.GetProperty("access").GetString()!, json.GetProperty("refresh").GetString()!);
    }

    private static Task<HttpResponseMessage> GetAsync(HttpClient node, string path, string tenant, string? bearer) =>
        node.SendAsync(Request(HttpMethod.Get, path, tenant, bearer));

    private static async Task ShouldBeSessionRevokedAsync(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.ToString().Should().Contain("invalid_token");
        (await JsonAsync(response)).GetProperty("code").GetString().Should().Be("session_revoked");
    }

    [Fact]
    public async Task TheTwoNodes_ShouldBeSeparateProcesses_InTheExpectedMode()
    {
        var one = await JsonAsync(await Node1.GetAsync("/health"));
        var two = await JsonAsync(await Node2.GetAsync("/health"));

        one.GetProperty("node").GetString().Should().Be("node1");
        two.GetProperty("node").GetString().Should().Be("node2");
        var expected = Environment.GetEnvironmentVariable("EXPECTED_MODE");
        if (expected != null) one.GetProperty("mode").GetString().Should().Be(expected);
    }

    [Fact]
    public async Task ATokenIssuedOnOneNode_ShouldBeAcceptedOnTheOther_WithItsPermission()
    {
        var (access, _) = await LoginAsync(Node1, "acme", "admin@acme.test");

        var me = await GetAsync(Node2, "/api/me", "acme", access);
        me.StatusCode.Should().Be(HttpStatusCode.OK);
        (await JsonAsync(me)).GetProperty("node").GetString().Should().Be("node2");
        (await GetAsync(Node2, "/api/sales", "acme", access)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task SignOutOnOneNode_ShouldEndTheSessionOnTheOther_AtOnce()
    {
        var (access, refresh) = await LoginAsync(Node1, "acme", "admin@acme.test");
        (await GetAsync(Node2, "/api/me", "acme", access)).StatusCode.Should().Be(HttpStatusCode.OK);

        (await Node1.SendAsync(Request(HttpMethod.Post, "/api/auth/logout", "acme", access))).StatusCode.Should().Be(HttpStatusCode.NoContent);

        await ShouldBeSessionRevokedAsync(await GetAsync(Node2, "/api/me", "acme", access));
        (await Node2.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", "acme", body: new { refreshToken = refresh })))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AnAdministrativeRevocationOnOneNode_ShouldEndTheSessionOnTheOther()
    {
        var (access, _) = await LoginAsync(Node2, "acme", "other@acme.test");

        (await Node1.SendAsync(Request(HttpMethod.Post, "/admin/revoke", "acme", body: new { email = "other@acme.test" })))
            .StatusCode.Should().Be(HttpStatusCode.NoContent);

        await ShouldBeSessionRevokedAsync(await GetAsync(Node2, "/api/me", "acme", access));
    }

    [Fact]
    public async Task ARefreshTokenReplayedOnAnotherNode_ShouldRevokeTheWholeFamily()
    {
        var (_, first) = await LoginAsync(Node1, "globex", "admin@globex.test");
        var rotated = await Node1.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", "globex", body: new { refreshToken = first }));
        rotated.StatusCode.Should().Be(HttpStatusCode.OK);
        var second = (await JsonAsync(rotated)).GetProperty("refresh").GetString()!;

        // The already used token, replayed on the other node: refused, and the family is revoked.
        (await Node2.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", "globex", body: new { refreshToken = first })))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await Node1.SendAsync(Request(HttpMethod.Post, "/api/auth/refresh", "globex", body: new { refreshToken = second })))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the replay revoked the family, including the newest token");
    }

    private static async Task<string> TwoFactorTokenAsync(HttpClient node, string email)
    {
        var response = await node.SendAsync(Request(HttpMethod.Post, "/api/auth/login", "acme", body: new { email, password = Password }));
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await JsonAsync(response)).GetProperty("twoFactorToken").GetString()!;
    }

    private static async Task<string> SentCodeAsync(HttpClient node, string email)
    {
        var response = await node.GetAsync($"/test/code?destination={Uri.EscapeDataString(email)}");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await JsonAsync(response)).GetProperty("code").GetString()!;
    }

    private static Task<HttpResponseMessage> VerifyAsync(HttpClient node, string token, string code) =>
        node.SendAsync(Request(HttpMethod.Post, "/api/auth/2fa/verify", "acme", body: new { token, provider = "Email", code }));

    [Fact]
    public async Task TwoFactor_StartedOnOneNode_ShouldFinishOnTheOther()
    {
        var token = await TwoFactorTokenAsync(Node1, "mfa@acme.test");
        (await Node2.SendAsync(Request(HttpMethod.Post, "/api/auth/2fa/send", "acme", body: new { token, provider = "Email" })))
            .StatusCode.Should().Be(HttpStatusCode.NoContent, "node2 reads node1's token with the shared Data Protection keys");
        var code = await SentCodeAsync(Node1, "mfa@acme.test");

        var verified = await VerifyAsync(Node1, token, code);

        verified.StatusCode.Should().Be(HttpStatusCode.OK);
        var access = (await JsonAsync(verified)).GetProperty("access").GetString()!;
        (await GetAsync(Node2, "/api/sales", "acme", access)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await VerifyAsync(Node2, token, code)).StatusCode.Should().Be(HttpStatusCode.Unauthorized, "a challenge is single use on every node");
    }

    [Fact]
    public async Task TwoFactor_WrongCodesSplitAcrossNodes_ShouldBeLimitedInTotal()
    {
        var token = await TwoFactorTokenAsync(Node2, "mfa-limit@acme.test");
        (await Node1.SendAsync(Request(HttpMethod.Post, "/api/auth/2fa/send", "acme", body: new { token, provider = "Email" })))
            .StatusCode.Should().Be(HttpStatusCode.NoContent);
        var code = await SentCodeAsync(Node2, "mfa-limit@acme.test");

        // Five wrong codes, three on one node and two on the other: per-node counters would allow ten.
        for (var i = 0; i < 3; i++) (await VerifyAsync(Node1, token, "000000")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        for (var i = 0; i < 2; i++) (await VerifyAsync(Node2, token, "000000")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        (await VerifyAsync(Node1, token, code)).StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the challenge's five attempts are spent across both nodes");
        (await VerifyAsync(Node2, token, code)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task APlanChangeInvalidatedOnOneNode_ShouldApplyOnTheOther()
    {
        var (access, _) = await LoginAsync(Node1, "acme", "admin@acme.test");
        (await GetAsync(Node2, "/api/sales", "acme", access)).StatusCode.Should().Be(HttpStatusCode.OK, "node2 caches the plan with SALES");

        try
        {
            (await Node1.SendAsync(Request(HttpMethod.Post, "/admin/plan", "acme", body: new { include = false, invalidate = true })))
                .StatusCode.Should().Be(HttpStatusCode.OK);

            (await GetAsync(Node2, "/api/sales", "acme", access)).StatusCode.Should().Be(HttpStatusCode.Forbidden, "the shared cache generation changed");
            (await GetAsync(Node1, "/api/sales", "acme", access)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }
        finally
        {
            (await Node2.SendAsync(Request(HttpMethod.Post, "/admin/plan", "acme", body: new { include = true, invalidate = true })))
                .StatusCode.Should().Be(HttpStatusCode.OK);
        }

        (await GetAsync(Node1, "/api/sales", "acme", access)).StatusCode.Should().Be(HttpStatusCode.OK, "restored on node2, seen on node1");
    }

    [Fact]
    public async Task RawSqlNamingAnotherTenantsSchema_ShouldBeDeniedByTheTenantsDatabaseRole_OnBothNodes()
    {
        foreach (var node in new[] { Node1, Node2 })
        {
            var other = await JsonAsync(await GetAsync(node, "/test/cross-tenant?target=globex", "acme", null));
            other.GetProperty("read").GetBoolean().Should().BeFalse();
            other.GetProperty("sqlState").GetString().Should().Be("42501", "insufficient_privilege: the role has no access to globex");

            var own = await JsonAsync(await GetAsync(node, "/test/cross-tenant?target=acme", "acme", null));
            own.GetProperty("read").GetBoolean().Should().BeTrue("control: the role reads its own schema");
        }
    }

    [Fact]
    public async Task AUserOfOneTenant_ShouldNotSignInToTheOther_AndItsTokenShouldStayInItsTenant()
    {
        (await Node2.SendAsync(Request(HttpMethod.Post, "/api/auth/login", "globex", body: new { email = "admin@acme.test", password = Password })))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var (access, _) = await LoginAsync(Node1, "acme", "admin@acme.test");
        var me = await GetAsync(Node2, "/api/me", "globex", access);
        me.StatusCode.Should().Be(HttpStatusCode.OK);
        (await JsonAsync(me)).GetProperty("tenant").GetString().Should().Be("acme", "the token's verified claim decides the tenant, not the header");
    }

    [Fact]
    public async Task ManyInterleavedRequestsOfBothTenants_OnBothNodes_ShouldEachSeeOnlyTheirOwnRows()
    {
        // Pooled sessions are reused between requests of each tenant role; every request must read its own schema.
        var expected = new Dictionary<string, long>
        {
            ["acme"] = (await JsonAsync(await GetAsync(Node1, "/test/cross-tenant?target=acme", "acme", null))).GetProperty("count").GetInt64(),
            ["globex"] = (await JsonAsync(await GetAsync(Node1, "/test/cross-tenant?target=globex", "globex", null))).GetProperty("count").GetInt64(),
        };
        expected["acme"].Should().NotBe(expected["globex"], "the tenants have different numbers of users, so a mix-up shows");

        var calls = Enumerable.Range(0, 200).Select(async i =>
        {
            var tenant = i % 2 == 0 ? "acme" : "globex";
            var node = i % 4 < 2 ? Node1 : Node2;
            var json = await JsonAsync(await GetAsync(node, $"/test/cross-tenant?target={tenant}", tenant, null));
            return (tenant, count: json.GetProperty("count").GetInt64());
        });

        foreach (var (tenant, count) in await Task.WhenAll(calls))
        {
            count.Should().Be(expected[tenant], $"a request of {tenant} read {tenant}'s users");
        }
    }
}
