using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// <see cref="IAccessTokenSessionValidator"/> through a host's own endpoint, with the check of <c>UseTenantResolution</c>
/// turned off (<c>ValidateSecurityStamp = false</c>): the public check still reports the ended session.
/// </summary>
public class SessionValidatorHostTests : IAsyncLifetime
{
    private TenantDatabaseApi _api = null!;

    public async Task InitializeAsync()
    {
        _api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = ["user@a.test"] },
            configureSecurity: o => o.Jwt.ValidateSecurityStamp = false,
            mapExtra: app => app.MapGet("/api/session", async (HttpContext http, TenantContext tenant, IAccessTokenSessionValidator sessions) =>
                Results.Json(new { active = await sessions.IsSessionActiveAsync(http.User, tenant.TenantId!, http.RequestAborted) })));
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    private async Task<HttpResponseMessage> GetAsync(string path, string access)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("TenantId", "a");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        return await _api.Client.SendAsync(request);
    }

    private async Task<bool> IsActiveAsync(string access)
    {
        var response = await GetAsync("/api/session", access);
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("active").GetBoolean();
    }

    [Fact]
    public async Task TheValidator_ShouldReportASignOut_EvenWithTheMiddlewareCheckOff()
    {
        var (access, _) = await _api.LoginAsync("user@a.test", "a");
        (await IsActiveAsync(access)).Should().BeTrue();

        (await _api.PostAsync("/api/auth/logout", new { }, "a", access)).StatusCode.Should().Be(HttpStatusCode.NoContent);

        (await GetAsync("/api/me", access)).StatusCode.Should().Be(HttpStatusCode.OK, "control: the middleware check is off");
        (await IsActiveAsync(access)).Should().BeFalse();
    }
}
