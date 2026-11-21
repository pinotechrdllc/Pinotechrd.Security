using System.Security.Claims;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using NSubstitute;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class PinotechrdAuthManagerTwoFactorTests
{
    private const string Tenant = "tenant-clear-text-marker";
    private const string InvalidSession = "Invalid session";
    private const string InvalidCode = "Invalid or expired code";

    // Implementation details the forgery tests rely on: the purpose strings and the payload layout
    // [userId, tenantId, stamp, challengeId, expiresAtUnixMs].
    private const string TokenPurpose = "Pinotechrd.Security.TwoFactor.v2";
    private const string OldTokenPurpose = "Pinotechrd.Security.TwoFactor.v1";

    public sealed class TfUser : BaseSecurityUser;

    private static AuthManagerTestKit<TfUser> NewKit(
        bool withDataProtection = true,
        IPinotechrdMessageService? messageService = null,
        bool withAttemptStore = true) =>
        new(withDataProtection, messageService, tenant: Tenant, withAttemptStore: withAttemptStore);

    private static async Task<(AuthManagerTestKit<TfUser> Kit, TfUser User, string Token)> LoggedInAsync()
    {
        var kit = NewKit();
        var user = kit.AddUser("alice@x.test", twoFactor: true);
        var login = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant);
        return (kit, user, login.TwoFactorToken!);
    }

    private static IDataProtector Protector(AuthManagerTestKit<TfUser> kit) =>
        kit.DataProtection!.CreateProtector(TokenPurpose);

    private static string Payload(string userId, string tenant, string stamp, long expiresAtMs, string challenge = "c1") =>
        JsonSerializer.Serialize(new[] { userId, tenant, stamp, challenge, expiresAtMs.ToString() });

    private static int VerifyCalls(AuthManagerTestKit<TfUser> kit) =>
        kit.UserManager.ReceivedCalls().Count(c => c.GetMethodInfo().Name == nameof(UserManager<TfUser>.VerifyTwoFactorTokenAsync));

    private static async Task AssertNoTokensIssued(AuthManagerTestKit<TfUser> kit)
    {
        kit.TokenProvider.DidNotReceiveWithAnyArgs().GenerateAccessToken(default!);
        kit.TokenProvider.DidNotReceive().GenerateRefreshToken();
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
    }

    // ---- Login with two-factor ----------------------------------------------------------------

    [Fact]
    public async Task LoginAsync_ShouldRequireTwoFactorAndIssueNoTokens_WhenUserEnabledTwoFactor()
    {
        var kit = NewKit();
        var user = kit.AddUser("alice@x.test", twoFactor: true);

        var result = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant);

        result.RequiresTwoFactor.Should().BeTrue();
        result.Succeeded.Should().BeFalse();
        result.Token.Should().BeNull();
        result.TwoFactorProviders.Should().Equal("Email");
        result.TwoFactorToken.Should().NotBeNullOrEmpty();
        await AssertNoTokensIssued(kit);

        var token = result.TwoFactorToken!;
        token.Should().NotBe(user.Id.ToString());
        token.Should().NotContain(user.Id.ToString());
        token.Should().NotContain(Tenant);
        token.Should().NotContain(kit.StampOf(user));
        // The token is encoded; its decoded bytes must not hold the values in clear text either.
        var decoded = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        decoded.Should().NotContain(user.Id.ToString()).And.NotContain(Tenant).And.NotContain(kit.StampOf(user));
    }

    [Fact]
    public async Task LoginAsync_ShouldFailWithoutRequiringTwoFactor_WhenTwoFactorIsEnabledAndNoDataProtectionProvider()
    {
        var kit = NewKit(withDataProtection: false);
        kit.AddUser("alice@x.test", twoFactor: true);

        var result = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be("Two-factor sign-in is not available");
        result.RequiresTwoFactor.Should().BeFalse();
        result.TwoFactorToken.Should().BeNull();
        result.Token.Should().BeNull();
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task LoginAsync_ShouldFailWithNotAvailable_WhenTwoFactorIsEnabledAndThereIsNoAttemptStore()
    {
        var kit = NewKit(withAttemptStore: false);
        kit.AddUser("alice@x.test", twoFactor: true);

        var result = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be("Two-factor sign-in is not available");
        result.RequiresTwoFactor.Should().BeFalse();
        result.TwoFactorToken.Should().BeNull();
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task LoginAsync_ShouldNotIssueATwoFactorToken_WhenPasswordIsWrong()
    {
        var kit = NewKit();
        kit.AddUser("alice@x.test", twoFactor: true);

        var result = await kit.Manager.LoginAsync("alice@x.test", "wrong", Tenant);

        result.RequiresTwoFactor.Should().BeFalse();
        result.TwoFactorToken.Should().BeNull();
        result.ErrorMessage.Should().Be("Invalid credentials");
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFailClosed_WhenThereIsNoDataProtectionProvider()
    {
        var kit = NewKit(withDataProtection: false);
        var user = kit.AddUser("alice@x.test", twoFactor: true);

        var providers = await kit.Manager.GetTwoFactorProvidersAsync(user.Id.ToString());
        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(user.Id.ToString(), "Email", kit.CodeFor(user), Tenant);

        providers.Should().BeEmpty();
        verify.Succeeded.Should().BeFalse();
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task TwoFactorMethods_ShouldFailClosed_WhenThereIsNoAttemptStore()
    {
        var kit = NewKit(withAttemptStore: false);
        var user = kit.AddUser("alice@x.test", twoFactor: true);
        // Forged with the manager's own key ring, so only the missing attempt store can make it fail.
        var expires = kit.Time.GetUtcNow().AddMinutes(1).ToUnixTimeMilliseconds();
        var token = Protector(kit).Protect(Payload(user.Id.ToString(), Tenant, kit.StampOf(user), expires));

        (await kit.Manager.GetTwoFactorProvidersAsync(token)).Should().BeEmpty();
        (await kit.Manager.SendTwoFactorCodeAsync(token, "Email")).Succeeded.Should().BeFalse();
        (await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant)).Succeeded.Should().BeFalse();
        await AssertNoTokensIssued(kit);
    }

    // ---- Raw ids and garbage are not sessions -------------------------------------------------

    [Fact]
    public async Task TwoFactorMethods_ShouldRejectARawUserId()
    {
        var (kit, user, _) = await LoggedInAsync();
        var rawId = user.Id.ToString();

        var providers = await kit.Manager.GetTwoFactorProvidersAsync(rawId);
        var send = await kit.Manager.SendTwoFactorCodeAsync(rawId, "Email");
        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(rawId, "Email", kit.CodeFor(user), Tenant);

        providers.Should().BeEmpty();
        send.Succeeded.Should().BeFalse();
        send.ErrorMessage.Should().Be(InvalidSession);
        verify.Succeeded.Should().BeFalse();
        verify.ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-token")]
    [InlineData("AAAA")]
    public async Task TwoFactorMethods_ShouldRejectEmptyOrGarbageTokens(string token)
    {
        var (kit, user, _) = await LoggedInAsync();

        (await kit.Manager.GetTwoFactorProvidersAsync(token)).Should().BeEmpty();
        (await kit.Manager.SendTwoFactorCodeAsync(token, "Email")).ErrorMessage.Should().Be(InvalidSession);
        (await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant)).ErrorMessage
            .Should().Be(InvalidSession);
    }

    [Fact]
    public async Task TwoFactorMethods_ShouldRejectATamperedToken()
    {
        var (kit, user, token) = await LoggedInAsync();
        var middle = token.Length / 2;
        var flipped = token[middle] == 'A' ? 'B' : 'A';
        var tampered = token[..middle] + flipped + token[(middle + 1)..];
        var truncated = token[..^4];

        foreach (var bad in new[] { tampered, truncated, token + "A" })
        {
            (await kit.Manager.GetTwoFactorProvidersAsync(bad)).Should().BeEmpty();
            (await kit.Manager.VerifyTwoFactorCodeAsync(bad, "Email", kit.CodeFor(user), Tenant)).ErrorMessage
                .Should().Be(InvalidSession);
        }

        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task TwoFactorMethods_ShouldRejectATokenProtectedByAnotherKeyRing()
    {
        var (kit, user, _) = await LoggedInAsync();
        var expires = kit.Time.GetUtcNow().AddMinutes(5).ToUnixTimeMilliseconds();
        var foreign = new EphemeralDataProtectionProvider().CreateProtector(TokenPurpose)
            .Protect(Payload(user.Id.ToString(), Tenant, kit.StampOf(user), expires));

        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(foreign, "Email", kit.CodeFor(user), Tenant);

        verify.ErrorMessage.Should().Be(InvalidSession);
    }

    [Fact]
    public async Task Token_ShouldBeRejected_WhenThePayloadHasTheWrongShape()
    {
        var (kit, user, _) = await LoggedInAsync();
        var id = user.Id.ToString();
        var shapes = new[]
        {
            "[]", "{}", "null", "not json",
            JsonSerializer.Serialize(new[] { id, Tenant, "s" }),
            JsonSerializer.Serialize(new[] { id, Tenant, "s", "c", "notanumber" }),
            JsonSerializer.Serialize(new[] { id, Tenant, "s", "c", "-5" }),
            JsonSerializer.Serialize(new[] { string.Empty, Tenant, "s", "c", "99999999999999" })
        };

        foreach (var shape in shapes)
        {
            var forged = Protector(kit).Protect(shape);
            var verify = await kit.Manager.VerifyTwoFactorCodeAsync(forged, "Email", kit.CodeFor(user), Tenant);
            verify.Succeeded.Should().BeFalse(shape);
        }
    }

    // ---- Verification ------------------------------------------------------------------------

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldIssueTokensForTheLoginTenantRenewStampAndResetFailures_WhenCodeIsCorrect()
    {
        var (kit, user, token) = await LoggedInAsync();
        var stampBefore = kit.StampOf(user);
        var code = kit.CodeFor(user);
        IEnumerable<Claim>? issuedClaims = null;
        kit.TokenProvider.GenerateAccessToken(Arg.Do<IEnumerable<Claim>>(c => issuedClaims = c.ToList()));

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", code, Tenant);

        result.Succeeded.Should().BeTrue();
        result.RequiresTwoFactor.Should().BeFalse();
        result.Token!.AccessToken.Should().Be("access-token");
        result.UserId.Should().Be(user.Id.ToString());
        issuedClaims.Should().Contain(c => c.Type == "tenant_id" && c.Value == Tenant);
        await kit.RefreshStore.Received(1).SaveAsync(
            user.Id.ToString(), Tenant, "refresh-token", Arg.Any<DateTime>(),
            Arg.Is<string?>(f => !string.IsNullOrEmpty(f)), Arg.Is<string?>(st => st == kit.StampOf(user)), Arg.Any<CancellationToken>());
        await kit.UserManager.Received(1).UpdateSecurityStampAsync(user);
        kit.StampOf(user).Should().NotBe(stampBefore);
        await kit.UserManager.Received(1).ResetAccessFailedCountAsync(user);
        await kit.UserManager.DidNotReceive().AccessFailedAsync(user);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRejectWithInvalidSession_WhenTenantDiffersFromTheLoginTenant()
    {
        var (kit, user, token) = await LoggedInAsync();

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), "other-tenant");

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRejectATenantDifferingOnlyInCase()
    {
        var (kit, user, token) = await LoggedInAsync();

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant.ToUpperInvariant());

        result.ErrorMessage.Should().Be(InvalidSession);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFailAndCountTheFailure_WhenCodeIsWrong()
    {
        var (kit, user, token) = await LoggedInAsync();

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(InvalidCode);
        await kit.UserManager.Received(1).AccessFailedAsync(user);
        await kit.UserManager.DidNotReceiveWithAnyArgs().ResetAccessFailedCountAsync(default!);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldAllowRetryWithCorrectCode_AfterAWrongCode()
    {
        var (kit, user, token) = await LoggedInAsync();

        await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);
        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRejectWithoutVerifyingTheCode_WhenUserIsLockedOut()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.LockOut(user);

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeFalse();
        await kit.UserManager.DidNotReceiveWithAnyArgs().VerifyTwoFactorTokenAsync(default!, default!, default!);
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRejectWithInvalidSession_WhenSecurityStampChangedAfterIssue()
    {
        var (kit, user, token) = await LoggedInAsync();
        var code = kit.CodeFor(user);
        kit.ChangeStamp(user);

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", code, Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(InvalidSession);
        (await kit.Manager.GetTwoFactorProvidersAsync(token)).Should().BeEmpty();
        (await kit.Manager.SendTwoFactorCodeAsync(token, "Email")).ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFail_WhenTheStampCannotBeRenewed()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.MakeStampUpdateFail(user);

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeFalse();
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFailOnReplayOfTheSameTokenAndCode()
    {
        var (kit, user, token) = await LoggedInAsync();
        var code = kit.CodeFor(user);

        var first = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", code, Tenant);
        var replay = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", code, Tenant);

        first.Succeeded.Should().BeTrue();
        replay.Succeeded.Should().BeFalse();
        kit.TokenProvider.Received(1).GenerateRefreshToken();
    }

    // ---- Expiry (TimeProvider) ---------------------------------------------------------------

    [Fact]
    public async Task Token_ShouldBeAcceptedAtFourFiftyNine_AndRejectedAtFiveMinutes()
    {
        var (kit, user, token) = await LoggedInAsync();

        kit.Time.Advance(TimeSpan.FromMinutes(4) + TimeSpan.FromSeconds(59));
        (await kit.Manager.GetTwoFactorProvidersAsync(token)).Should().Equal("Email");

        kit.Time.Advance(TimeSpan.FromSeconds(1));
        (await kit.Manager.GetTwoFactorProvidersAsync(token)).Should().BeEmpty();
        (await kit.Manager.SendTwoFactorCodeAsync(token, "Email")).ErrorMessage.Should().Be(InvalidSession);
        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        verify.Succeeded.Should().BeFalse();
        verify.ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task Token_ShouldVerifySuccessfully_AtFourFiftyNine()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.Time.Advance(TimeSpan.FromMinutes(4) + TimeSpan.FromSeconds(59));

        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        verify.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task Token_ShouldBeRejected_WhenItsOwnExpiryIsInThePastEvenIfProtectedCorrectly()
    {
        var (kit, user, _) = await LoggedInAsync();
        var past = kit.Time.GetUtcNow().AddSeconds(-1).ToUnixTimeMilliseconds();
        var forged = Protector(kit).Protect(Payload(user.Id.ToString(), Tenant, kit.StampOf(user), past));

        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(forged, "Email", kit.CodeFor(user), Tenant);

        verify.ErrorMessage.Should().Be(InvalidSession);
    }

    // Control for the forged-token tests: the same layout with a future expiry is accepted.
    [Fact]
    public async Task Token_ShouldBeAccepted_WhenForgedWithTheSameLayoutAndAFutureExpiry()
    {
        var (kit, user, _) = await LoggedInAsync();
        var future = kit.Time.GetUtcNow().AddMinutes(1).ToUnixTimeMilliseconds();
        var forged = Protector(kit).Protect(Payload(user.Id.ToString(), Tenant, kit.StampOf(user), future));

        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(forged, "Email", kit.CodeFor(user), Tenant);

        verify.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task Token_ShouldBeRejected_WhenMadeWithTheOldV1Purpose()
    {
        var (kit, user, _) = await LoggedInAsync();
        var v1 = kit.DataProtection!.CreateProtector(OldTokenPurpose).ToTimeLimitedDataProtector()
            .Protect(JsonSerializer.Serialize(new[] { user.Id.ToString(), Tenant, kit.StampOf(user) }), TimeSpan.FromMinutes(5));

        (await kit.Manager.GetTwoFactorProvidersAsync(v1)).Should().BeEmpty();
        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(v1, "Email", kit.CodeFor(user), Tenant);

        verify.ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
    }

    // ---- Tenant binding ----------------------------------------------------------------------

    [Fact]
    public async Task TwoFactorMethods_ShouldRejectTheToken_WhenTheRequestContextHoldsAnotherTenant()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.TenantContext!.SetTenant("tenant-other");

        (await kit.Manager.GetTwoFactorProvidersAsync(token)).Should().BeEmpty();
        (await kit.Manager.SendTwoFactorCodeAsync(token, "Email")).ErrorMessage.Should().Be(InvalidSession);
        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        verify.Succeeded.Should().BeFalse();
        verify.ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task TwoFactorMethods_ShouldRejectTheToken_WhenTheContextHasNoTenant()
    {
        var kit = new AuthManagerTestKit<TfUser>(tenant: null);
        var user = kit.AddUser("alice@x.test", twoFactor: true);
        var expires = kit.Time.GetUtcNow().AddMinutes(1).ToUnixTimeMilliseconds();
        // Forged with the manager's own key ring, so only the missing tenant can make it fail.
        var token = Protector(kit).Protect(Payload(user.Id.ToString(), Tenant, kit.StampOf(user), expires));

        (await kit.Manager.GetTwoFactorProvidersAsync(token)).Should().BeEmpty();
        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        verify.Succeeded.Should().BeFalse();
        verify.ErrorMessage.Should().Be(InvalidSession);
    }

    // ---- Inactive users ----------------------------------------------------------------------

    [Fact]
    public async Task TwoFactorMethods_ShouldRejectWithInvalidSession_WhenTheUserBecameInactive()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.MakeInactive(user);

        (await kit.Manager.GetTwoFactorProvidersAsync(token)).Should().BeEmpty();
        (await kit.Manager.SendTwoFactorCodeAsync(token, "Email")).ErrorMessage.Should().Be(InvalidSession);
        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        verify.ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
    }

    // ---- Attempt limit -----------------------------------------------------------------------

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRefuseTheSixthAttemptWithoutVerifyingTheCode()
    {
        var (kit, _, token) = await LoggedInAsync();

        for (var i = 1; i <= 5; i++)
        {
            var wrong = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);
            wrong.ErrorMessage.Should().Be(InvalidCode);
        }
        VerifyCalls(kit).Should().Be(5);

        var sixth = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);

        sixth.Succeeded.Should().BeFalse();
        sixth.ErrorMessage.Should().Be(InvalidCode);
        VerifyCalls(kit).Should().Be(5);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRejectTheCorrectCode_AfterFiveFailuresOnTheSameToken()
    {
        var (kit, user, token) = await LoggedInAsync();
        for (var i = 0; i < 5; i++) await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(InvalidCode);
        VerifyCalls(kit).Should().Be(5);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldVerifyAtMostFiveTimes_WhenTwentyWrongGuessesRunConcurrently()
    {
        var (kit, _, token) = await LoggedInAsync();

        var results = await Task.WhenAll(Enumerable.Range(0, 20)
            .Select(i => Task.Run(() => kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", $"{i:000000}", Tenant))));

        results.Should().AllSatisfy(r => r.Succeeded.Should().BeFalse());
        VerifyCalls(kit).Should().BeLessThanOrEqualTo(5);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldGiveEachTokenItsOwnAttemptBudget()
    {
        var (kit, user, first) = await LoggedInAsync();
        for (var i = 0; i < 6; i++) await kit.Manager.VerifyTwoFactorCodeAsync(first, "Email", "000000", Tenant);
        var second = (await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant)).TwoFactorToken!;

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(second, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFail_WhenCountingTheFailureReturnsFailed()
    {
        var (kit, _, token) = await LoggedInAsync();
        kit.UserManager.AccessFailedAsync(Arg.Any<TfUser>()).Returns(Task.FromResult(IdentityResult.Failed()));

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(InvalidCode);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFailWithoutRenewingTheStamp_WhenTheUserGetsLockedOutAfterTheCodeIsAccepted()
    {
        var (kit, user, token) = await LoggedInAsync();
        var code = kit.CodeFor(user);
        var stamp = kit.StampOf(user);
        // The check before the code says free, the check after the code was accepted says locked.
        kit.UserManager.IsLockedOutAsync(user).Returns(Task.FromResult(false), Task.FromResult(true));

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", code, Tenant);

        result.Succeeded.Should().BeFalse();
        kit.StampOf(user).Should().Be(stamp);
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
        await AssertNoTokensIssued(kit);
    }

    // ---- Providers ---------------------------------------------------------------------------

    [Theory]
    [InlineData("Sms")]
    [InlineData("email")]
    [InlineData("EMAIL")]
    [InlineData("")]
    [InlineData("Email ")]
    public async Task SendTwoFactorCodeAsync_ShouldFailWithoutGeneratingACode_WhenProviderIsUnknown(string provider)
    {
        var messages = Substitute.For<IPinotechrdMessageService>();
        var kit = NewKit(messageService: messages);
        kit.AddUser("alice@x.test", twoFactor: true);
        var token = (await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant)).TwoFactorToken!;

        var result = await kit.Manager.SendTwoFactorCodeAsync(token, provider);

        result.Succeeded.Should().BeFalse();
        await kit.UserManager.DidNotReceiveWithAnyArgs().GenerateTwoFactorTokenAsync(default!, default!);
        await messages.DidNotReceiveWithAnyArgs().SendCodeAsync(default!, default!, default);
    }

    [Fact]
    public async Task SendTwoFactorCodeAsync_ShouldReturnInvalidSessionAndSendNothing_WhenTheUserIsLockedOut()
    {
        var messages = Substitute.For<IPinotechrdMessageService>();
        var kit = NewKit(messageService: messages);
        var user = kit.AddUser("alice@x.test", twoFactor: true);
        var token = (await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant)).TwoFactorToken!;
        kit.LockOut(user);

        var result = await kit.Manager.SendTwoFactorCodeAsync(token, "Email");

        result.ErrorMessage.Should().Be(InvalidSession);
        await kit.UserManager.DidNotReceiveWithAnyArgs().GenerateTwoFactorTokenAsync(default!, default!);
        await messages.DidNotReceiveWithAnyArgs().SendCodeAsync(default!, default!, default);
    }

    [Theory]
    [InlineData("Sms")]
    [InlineData("email")]
    [InlineData("")]
    public async Task VerifyTwoFactorCodeAsync_ShouldReturnInvalidCodeWithoutThrowing_WhenProviderIsUnknown(string provider)
    {
        var (kit, user, token) = await LoggedInAsync();

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, provider, kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(InvalidCode);
        await AssertNoTokensIssued(kit);
    }

    // ---- A token for X never works for Y ----------------------------------------------------

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldNotLetTokenOfUserXVerifyTheCodeOfUserY()
    {
        var kit = NewKit();
        var x = kit.AddUser("x@x.test", twoFactor: true);
        var y = kit.AddUser("y@x.test", twoFactor: true);
        var tokenX = (await kit.Manager.LoginAsync("x@x.test", AuthManagerTestKit<TfUser>.Password, Tenant)).TwoFactorToken!;
        await kit.Manager.LoginAsync("y@x.test", AuthManagerTestKit<TfUser>.Password, Tenant);

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(tokenX, "Email", kit.CodeFor(y), Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(InvalidCode);
        await kit.UserManager.Received(1).AccessFailedAsync(x);
        await kit.UserManager.DidNotReceive().AccessFailedAsync(y);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRejectATokenWhoseUserIdWasSwappedForAnotherUser()
    {
        var kit = NewKit();
        kit.AddUser("x@x.test", twoFactor: true);
        var y = kit.AddUser("y@x.test", twoFactor: true);
        var tokenX = (await kit.Manager.LoginAsync("x@x.test", AuthManagerTestKit<TfUser>.Password, Tenant)).TwoFactorToken!;
        var protector = Protector(kit);

        // Forge, with the real key ring, a payload that keeps X's stamp but names Y.
        var parts = JsonSerializer.Deserialize<string[]>(protector.Unprotect(tokenX))!;
        parts[0] = y.Id.ToString();
        var swapped = protector.Protect(JsonSerializer.Serialize(parts));

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(swapped, "Email", kit.CodeFor(y), Tenant);

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
    }

    // ---- Sending a code ----------------------------------------------------------------------

    [Fact]
    public async Task SendTwoFactorCodeAsync_ShouldSendTheCodeToTheTokenUser_WhenTokenIsValid()
    {
        var messages = Substitute.For<IPinotechrdMessageService>();
        var kit = NewKit(messageService: messages);
        var user = kit.AddUser("alice@x.test", twoFactor: true);
        var token = (await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant)).TwoFactorToken!;

        var result = await kit.Manager.SendTwoFactorCodeAsync(token, "Email");

        result.Succeeded.Should().BeTrue();
        await messages.Received(1).SendCodeAsync("alice@x.test", kit.CodeFor(user), SecurityCodeType.TwoFactor);
    }

    [Fact]
    public async Task GetTwoFactorProvidersAsync_ShouldReturnTheUserProviders_WhenTokenIsValid()
    {
        var (kit, _, token) = await LoggedInAsync();

        var providers = await kit.Manager.GetTwoFactorProvidersAsync(token);

        providers.Should().Equal("Email");
    }

    // ---- Recording a failed code (concurrency) -----------------------------------------------

    private static IdentityResult Concurrency() => IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure());

    private static int Calls(AuthManagerTestKit<TfUser> kit, string method) =>
        kit.UserManager.ReceivedCalls().Count(c => c.GetMethodInfo().Name == method);

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRecordTheFailureAndReloadTheUser_WhenTheCountConflictsTwiceThenSucceeds()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.UserManager.AccessFailedAsync(Arg.Any<TfUser>()).Returns(
            Task.FromResult(Concurrency()), Task.FromResult(Concurrency()), Task.FromResult(IdentityResult.Success));
        var findsBefore = Calls(kit, nameof(UserManager<TfUser>.FindByIdAsync));

        var wrong = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);

        wrong.ErrorMessage.Should().Be(InvalidCode);
        Calls(kit, nameof(UserManager<TfUser>.AccessFailedAsync)).Should().Be(3);
        // One lookup to read the token, then one reload before each retry.
        (Calls(kit, nameof(UserManager<TfUser>.FindByIdAsync)) - findsBefore).Should().Be(3);

        var right = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);
        right.Succeeded.Should().BeTrue("the challenge stays usable once the failure was recorded");
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldExhaustTheChallenge_WhenTheCountConflictsOnEveryTry()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.UserManager.AccessFailedAsync(Arg.Any<TfUser>()).Returns(Task.FromResult(Concurrency()));

        var wrong = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);
        var verifiesAfterFirst = VerifyCalls(kit);
        var right = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        wrong.Succeeded.Should().BeFalse();
        right.Succeeded.Should().BeFalse("a failure that could not be recorded spends the challenge");
        right.ErrorMessage.Should().Be(InvalidCode);
        VerifyCalls(kit).Should().Be(verifiesAfterFirst, "the code of a spent challenge is not verified");
        Calls(kit, nameof(UserManager<TfUser>.AccessFailedAsync)).Should().BeGreaterThan(1).And.BeLessThanOrEqualTo(100);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldExhaustTheChallenge_WhenRecordingTheFailureFailsForAnyOtherReason()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.UserManager.AccessFailedAsync(Arg.Any<TfUser>())
            .Returns(Task.FromResult(IdentityResult.Failed(new IdentityError { Code = "Boom", Description = "boom" })));

        await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);
        var right = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        Calls(kit, nameof(UserManager<TfUser>.AccessFailedAsync)).Should().Be(1, "only a concurrency conflict is retried");
        right.Succeeded.Should().BeFalse();
        VerifyCalls(kit).Should().Be(1);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldNotSpendTheChallenge_WhenTheFailureIsRecordedOnTheFirstTry()
    {
        var (kit, user, token) = await LoggedInAsync();

        await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", "000000", Tenant);
        var right = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        right.Succeeded.Should().BeTrue();
    }

    // ---- The correct-code path ----------------------------------------------------------------

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFail_WhenResettingTheFailureCountKeepsFailing()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.UserManager.ResetAccessFailedCountAsync(Arg.Any<TfUser>())
            .Returns(Task.FromResult(IdentityResult.Failed(new IdentityError { Code = "Boom" })));

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeFalse();
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFail_WhenResettingTheFailureCountConflictsOnEveryTry()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.UserManager.ResetAccessFailedCountAsync(Arg.Any<TfUser>()).Returns(Task.FromResult(Concurrency()));

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeFalse();
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldSucceed_WhenResettingTheFailureCountConflictsOnceThenSucceeds()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.UserManager.ResetAccessFailedCountAsync(Arg.Any<TfUser>())
            .Returns(Task.FromResult(Concurrency()), Task.FromResult(IdentityResult.Success));

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldRetryTheStampRenewal_WhenItConflictsWhileTheStampIsStillTheTokens()
    {
        var (kit, user, token) = await LoggedInAsync();
        kit.UserManager.UpdateSecurityStampAsync(Arg.Any<TfUser>()).Returns(
            Task.FromResult(Concurrency()),
            Task.FromResult(IdentityResult.Success));

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", kit.CodeFor(user), Tenant);

        result.Succeeded.Should().BeTrue();
        await kit.UserManager.Received(2).UpdateSecurityStampAsync(user);
    }

    [Fact]
    public async Task VerifyTwoFactorCodeAsync_ShouldFail_WhenAConcurrentVerificationAlreadyRenewedTheStamp()
    {
        var (kit, user, token) = await LoggedInAsync();
        var code = kit.CodeFor(user);
        kit.UserManager.UpdateSecurityStampAsync(Arg.Any<TfUser>()).Returns(_ =>
        {
            kit.ChangeStamp(user); // the other verification of the same token got there first
            return Task.FromResult(Concurrency());
        });

        var result = await kit.Manager.VerifyTwoFactorCodeAsync(token, "Email", code, Tenant);

        result.Succeeded.Should().BeFalse();
        await kit.UserManager.Received(1).UpdateSecurityStampAsync(user);
        await AssertNoTokensIssued(kit);
    }
}
