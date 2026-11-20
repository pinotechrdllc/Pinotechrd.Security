using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tests.Core;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// The security events (<see cref="SecurityEvents"/>) through the real pipeline and Identity: which event each outcome
/// logs, with which properties, and that no event carries an email, a password, a token or a code.
/// </summary>
public class SecurityEventsTests
{
    private const string Alice = "alice@a.test";
    private const string Bob = "bob@b.test";

    private static async Task<(TenantDatabaseApi Api, CapturedLogs Logs)> StartAsync()
    {
        var logs = new CapturedLogs();
        var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = [Alice], ["b"] = [Bob] },
            configureBuilder: b => b.Logging.AddProvider(logs));
        return (api, logs);
    }

    private static Task<HttpResponseMessage> LoginAsync(TenantDatabaseApi api, string email, string password, string tenant) =>
        api.PostAsync("/api/auth/login", new LoginRequest(email, password), tenant);

    private static async Task<string> RefreshOkAsync(TenantDatabaseApi api, string refresh, string tenant)
    {
        var response = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), tenant);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("refresh").GetString()!;
    }

    private static CapturedLog Single(CapturedLogs logs, EventId id)
    {
        var entry = logs.Events(id.Id).Should().ContainSingle().Subject;
        entry.Category.Should().Be(SecurityEvents.Category);
        entry.EventId.Name.Should().Be(id.Name);
        return entry;
    }

    /// <summary>No library log entry may carry personal data or a credential.</summary>
    private static void ShouldLeakNothing(CapturedLogs logs, params string[] secrets)
    {
        var library = logs.Entries.Where(e => e.Category.StartsWith("Pinotechrd", StringComparison.Ordinal)).ToArray();
        foreach (var secret in secrets.Where(s => !string.IsNullOrEmpty(s)))
        {
            library.Should().NotContain(e => e.Message.Contains(secret, StringComparison.Ordinal)
                || e.Properties.Values.Any(v => v != null && v.ToString()!.Contains(secret, StringComparison.Ordinal)), secret);
        }
    }

    [Fact]
    public async Task ASuccessfulSignIn_ShouldLogTokensIssued_WithTenantUserAndMethod()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;

        var (access, refresh) = await api.LoginAsync(Alice, "a");

        var entry = Single(logs, SecurityEvents.TokensIssued);
        entry.Level.Should().Be(LogLevel.Information);
        entry.Property("TenantId").Should().Be("a");
        entry.Property("UserId").Should().NotBeNullOrEmpty().And.NotBe(Alice);
        entry.Property("Method").Should().Be("Password");
        ShouldLeakNothing(logs, Alice, TenantDatabaseApi.Password, access, refresh);
    }

    [Fact]
    public async Task AWrongPassword_AndAnUnknownUser_ShouldLogSignInFailed_WithTheReason_AndNoEmailOrPassword()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;

        (await LoginAsync(api, Alice, "Wrong-passw0rd!", "a")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await LoginAsync(api, "nobody@a.test", "Wrong-passw0rd!", "a")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var failures = logs.Events(SecurityEvents.SignInFailed.Id);
        failures.Should().HaveCount(2);
        failures[0].Property("Reason").Should().Be("WrongPassword");
        failures[0].Property("UserId").Should().NotBeNullOrEmpty();
        failures[1].Property("Reason").Should().Be("UnknownUser");
        failures[1].Property("UserId").Should().BeEmpty();
        failures.Should().OnlyContain(e => e.Property("TenantId") == "a" && e.Level == LogLevel.Information);
        ShouldLeakNothing(logs, Alice, "nobody@a.test", "Wrong-passw0rd!");
    }

    [Fact]
    public async Task TheFailureThatLocksTheAccount_ShouldLogAccountLockedOutOnce_AndLaterAttemptsReasonLockedOut()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;

        // Identity's default: five failures lock the account.
        for (var i = 0; i < 6; i++) await LoginAsync(api, Alice, "Wrong-passw0rd!", "a");

        var locked = Single(logs, SecurityEvents.AccountLockedOut);
        locked.Level.Should().Be(LogLevel.Warning);
        locked.Property("TenantId").Should().Be("a");
        logs.Events(SecurityEvents.SignInFailed.Id).Select(e => e.Property("Reason"))
            .Should().Equal("WrongPassword", "WrongPassword", "WrongPassword", "WrongPassword", "WrongPassword", "LockedOut");
    }

    [Fact]
    public async Task ARefreshThenAReplay_ShouldLogTokensIssuedByRefresh_ThenRefreshTokenReused_WithUserAndFamily()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;
        var (_, refresh) = await api.LoginAsync(Alice, "a");

        var next = await RefreshOkAsync(api, refresh, "a");
        (await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "a")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        logs.Events(SecurityEvents.TokensIssued.Id).Select(e => e.Property("Method")).Should().Equal("Password", "Refresh");
        var reused = Single(logs, SecurityEvents.RefreshTokenReused);
        reused.Level.Should().Be(LogLevel.Warning);
        reused.Property("TenantId").Should().Be("a");
        reused.Property("UserId").Should().Be(logs.Events(SecurityEvents.TokensIssued.Id)[0].Property("UserId"));
        reused.Property("FamilyId").Should().NotBeNullOrEmpty();
        ShouldLeakNothing(logs, refresh, next);
    }

    [Fact]
    public async Task ARefreshTokenOfAnotherTenant_ShouldLogRefreshTokenTenantMismatch()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;
        var (_, refresh) = await api.LoginAsync(Alice, "a");

        (await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "b")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        Single(logs, SecurityEvents.RefreshTokenTenantMismatch).Property("TenantId").Should().Be("b");
    }

    [Fact]
    public async Task AnUnknownRefreshToken_ShouldLogRefreshRefusedNotFound()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;

        await api.PostAsync("/api/auth/refresh", new RefreshRequest("not-a-token"), "a");

        Single(logs, SecurityEvents.RefreshRefused).Property("Reason").Should().Be("NotFound");
        ShouldLeakNothing(logs, "not-a-token");
    }

    [Fact]
    public async Task SignOut_ShouldLogSessionsEnded_AndTheEndedTokenItsRefusal()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;
        var (access, _) = await api.LoginAsync(Alice, "a");
        await api.PostAsync("/api/auth/logout", new { }, "a", access);

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("TenantId", "a");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        (await api.Client.SendAsync(request)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var ended = Single(logs, SecurityEvents.SessionsEnded);
        ended.Property("Trigger").Should().Be("SignOut");
        ended.Property("TenantId").Should().Be("a");
        Single(logs, SecurityEvents.AccessTokenSessionEnded).Property("TenantId").Should().Be("a");
        ShouldLeakNothing(logs, access);
    }

    // ---- Two-factor, through the manager -----------------------------------------------------------

    public sealed class TfUser : BaseSecurityUser;

    [Fact]
    public async Task WrongTwoFactorCodes_ShouldLogEachFailure_AndExhaustedFromTheLastAllowedAttemptOn()
    {
        var logs = new CapturedLogs();
        var kit = new AuthManagerTestKit<TfUser>(loggerFactory: logs);
        var user = kit.AddUser("tf@x.test", twoFactor: true);
        var login = await kit.Manager.LoginAsync("tf@x.test", AuthManagerTestKit<TfUser>.Password, AuthManagerTestKit<TfUser>.DefaultTenant);

        for (var i = 0; i < 7; i++)
        {
            (await kit.Manager.VerifyTwoFactorCodeAsync(login.TwoFactorToken!, "Email", "000000", AuthManagerTestKit<TfUser>.DefaultTenant)).Succeeded.Should().BeFalse();
        }

        logs.Events(SecurityEvents.TwoFactorCodeFailed.Id).Should().HaveCount(5);
        // The fifth wrong code uses the last attempt; the sixth and seventh are past the limit.
        var exhausted = logs.Events(SecurityEvents.TwoFactorChallengeExhausted.Id);
        exhausted.Should().HaveCount(3);
        exhausted.Should().OnlyContain(e => e.Property("UserId") == user.Id.ToString()
            && e.Property("TenantId") == AuthManagerTestKit<TfUser>.DefaultTenant && e.Level == LogLevel.Warning);
        ShouldLeakNothing(logs, "tf@x.test", "000000", login.TwoFactorToken!);
    }

    [Fact]
    public async Task ACorrectTwoFactorCode_ShouldLogTokensIssuedByTwoFactor()
    {
        var logs = new CapturedLogs();
        var kit = new AuthManagerTestKit<TfUser>(loggerFactory: logs);
        var user = kit.AddUser("tf@x.test", twoFactor: true);
        var login = await kit.Manager.LoginAsync("tf@x.test", AuthManagerTestKit<TfUser>.Password, AuthManagerTestKit<TfUser>.DefaultTenant);
        var code = kit.CodeFor(user);

        (await kit.Manager.VerifyTwoFactorCodeAsync(login.TwoFactorToken!, "Email", code, AuthManagerTestKit<TfUser>.DefaultTenant)).Succeeded.Should().BeTrue();

        Single(logs, SecurityEvents.TokensIssued).Property("Method").Should().Be("TwoFactor");
        ShouldLeakNothing(logs, code);
    }

    [Fact]
    public async Task WithoutALoggerFactory_TheManagerShouldWorkAndLogNothing()
    {
        var kit = new AuthManagerTestKit<TfUser>();
        kit.AddUser("plain@x.test");

        (await kit.Manager.LoginAsync("plain@x.test", AuthManagerTestKit<TfUser>.Password, AuthManagerTestKit<TfUser>.DefaultTenant)).Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ASignInForAnotherTenant_ShouldLogTenantMismatch_WithTheResolvedTenant_NotTheArgument()
    {
        var logs = new CapturedLogs();
        var kit = new AuthManagerTestKit<TfUser>(loggerFactory: logs);
        kit.AddUser("plain@x.test");

        (await kit.Manager.LoginAsync("plain@x.test", AuthManagerTestKit<TfUser>.Password, "other-tenant")).Succeeded.Should().BeFalse();

        var entry = Single(logs, SecurityEvents.SignInFailed);
        entry.Property("Reason").Should().Be("TenantMismatch");
        entry.Property("TenantId").Should().Be(AuthManagerTestKit<TfUser>.DefaultTenant);
        ShouldLeakNothing(logs, "other-tenant", "plain@x.test");
    }

    [Fact]
    public async Task AnInactiveUser_ShouldLogSignInFailedInactive_WithItsId()
    {
        var logs = new CapturedLogs();
        var kit = new AuthManagerTestKit<TfUser>(loggerFactory: logs);
        var user = kit.AddUser("off@x.test");
        kit.MakeInactive(user);

        (await kit.Manager.LoginAsync("off@x.test", AuthManagerTestKit<TfUser>.Password, AuthManagerTestKit<TfUser>.DefaultTenant)).Succeeded.Should().BeFalse();

        var entry = Single(logs, SecurityEvents.SignInFailed);
        entry.Property("Reason").Should().Be("Inactive");
        entry.Property("UserId").Should().Be(user.Id.ToString());
    }

    [Fact]
    public async Task AValidatorThatRefuses_ShouldLogSignInFailedValidatorRefused_AndNoTokensIssued()
    {
        var logs = new CapturedLogs();
        var validator = Substitute.For<IIdentityValidator<TfUser>>();
        validator.ValidateAsync(Arg.Any<TfUser>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(IdentityValidationResult.Failure("No employee record"));
        var kit = new AuthManagerTestKit<TfUser>(identityValidator: validator, loggerFactory: logs);
        kit.AddUser("v@x.test");

        (await kit.Manager.LoginAsync("v@x.test", AuthManagerTestKit<TfUser>.Password, AuthManagerTestKit<TfUser>.DefaultTenant)).Succeeded.Should().BeFalse();

        Single(logs, SecurityEvents.SignInFailed).Property("Reason").Should().Be("ValidatorRefused");
        logs.Events(SecurityEvents.TokensIssued.Id).Should().BeEmpty();
        ShouldLeakNothing(logs, "No employee record");
    }

    [Fact]
    public async Task ARefreshAfterSignOut_ShouldLogRefreshRefusedRevoked()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;
        var (access, refresh) = await api.LoginAsync(Alice, "a");
        await api.PostAsync("/api/auth/logout", new { }, "a", access);

        (await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "a")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        Single(logs, SecurityEvents.RefreshRefused).Property("Reason").Should().Be("Revoked");
    }

    [Fact]
    public async Task ARefreshAfterAPasswordReset_ShouldLogRefreshRefusedStampChanged()
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;
        var (_, refresh) = await api.LoginAsync(Alice, "a");
        await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            // A stamp change that revokes no refresh token: only the stamp check can refuse the refresh.
            return await users.UpdateSecurityStampAsync((await users.FindByEmailAsync(Alice))!);
        });

        (await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), "a")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var entry = Single(logs, SecurityEvents.RefreshRefused);
        entry.Property("Reason").Should().Be("StampChanged");
        entry.Property("UserId").Should().NotBeNullOrEmpty();
    }

    [Theory]
    [InlineData("Revoked")]
    [InlineData("Deactivated")]
    [InlineData("Deleted")]
    public async Task AdministrativeEnds_ShouldLogSessionsEnded_WithTheirTrigger_AndTheTenant(string trigger)
    {
        var (api, logs) = await StartAsync();
        await using var _ = api;
        await api.LoginAsync(Alice, "a");

        await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var id = await users.GetUserIdAsync((await users.FindByEmailAsync(Alice))!);
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            return trigger switch
            {
                "Revoked" => await manager.RevokeUserSessionsAsync(id),
                "Deactivated" => await manager.SetUserActiveStatusAsync(id, false),
                _ => await manager.DeleteUserAsync(id),
            };
        });

        var entry = Single(logs, SecurityEvents.SessionsEnded);
        entry.Property("Trigger").Should().Be(trigger);
        entry.Property("TenantId").Should().Be("a");
        ShouldLeakNothing(logs, Alice);
    }

    // ---- Cache invalidation ------------------------------------------------------------------------

    [Fact]
    public async Task InvalidatingATenant_ShouldLogTenantCacheInvalidated()
    {
        var logs = new CapturedLogs();
        var store = new TenantCacheStore(
            Substitute.For<ISecurityStore>(),
            new MemoryDistributedCache(Microsoft.Extensions.Options.Options.Create(new MemoryDistributedCacheOptions())),
            Microsoft.Extensions.Options.Options.Create(new PinotechrdSecurityOptions()),
            logs);

        await store.InvalidateTenantAsync("tenant-a");

        Single(logs, SecurityEvents.TenantCacheInvalidated).Property("TenantId").Should().Be("tenant-a");
    }

    [Fact]
    public void EventIds_ShouldBeStableAndUnique()
    {
        var ids = typeof(SecurityEvents).GetFields().Where(f => f.FieldType == typeof(EventId)).Select(f => (EventId)f.GetValue(null)!).ToArray();

        ids.Select(e => e.Id).Should().BeEquivalentTo(Enumerable.Range(4201, 12)).And.OnlyHaveUniqueItems();
        ids.Should().OnlyContain(e => !string.IsNullOrEmpty(e.Name));
        SecurityEvents.SignInFailed.Id.Should().Be(4201);
        SecurityEvents.RefreshTokenReused.Id.Should().Be(4204);
        SecurityEvents.AccessTokenSessionEnded.Id.Should().Be(4210);
    }
}
