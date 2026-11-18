using System.Security.Claims;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
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

    // The purpose string is the only implementation detail the expiry and swap tests rely on.
    private const string TokenPurpose = "Pinotechrd.Security.TwoFactor.v1";

    public sealed class TfUser : BaseSecurityUser;

    private static AuthManagerTestKit<TfUser> NewKit(
        bool withDataProtection = true,
        IPinotechrdMessageService? messageService = null) =>
        new(withDataProtection, messageService);

    private static async Task<(AuthManagerTestKit<TfUser> Kit, TfUser User, string Token)> LoggedInAsync()
    {
        var kit = NewKit();
        var user = kit.AddUser("alice@x.test", twoFactor: true);
        var login = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<TfUser>.Password, Tenant);
        return (kit, user, login.TwoFactorToken!);
    }

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
        result.RequiresTwoFactor.Should().BeFalse();
        result.TwoFactorToken.Should().BeNull();
        result.Token.Should().BeNull();
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
        var foreign = new EphemeralDataProtectionProvider().CreateProtector(TokenPurpose).ToTimeLimitedDataProtector()
            .Protect($"[\"{user.Id}\",\"{Tenant}\",\"{kit.StampOf(user)}\"]", TimeSpan.FromMinutes(5));

        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(foreign, "Email", kit.CodeFor(user), Tenant);

        verify.ErrorMessage.Should().Be(InvalidSession);
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
        await kit.RefreshStore.Received(1).SaveAsync(user.Id.ToString(), Tenant, "refresh-token", Arg.Any<DateTime>());
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

    // ---- Expiry (no clock seam; see notes) ---------------------------------------------------

    [Fact]
    public async Task LoginAsync_ShouldIssueATokenThatExpiresInAboutFiveMinutes()
    {
        var (kit, _, token) = await LoggedInAsync();

        var protector = kit.DataProtection!.CreateProtector(TokenPurpose).ToTimeLimitedDataProtector();
        protector.Unprotect(token, out var expiration);

        expiration.Should().BeCloseTo(DateTimeOffset.UtcNow.AddMinutes(5), TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task TwoFactorMethods_ShouldRejectAnExpiredToken()
    {
        var (kit, user, token) = await LoggedInAsync();
        var protector = kit.DataProtection!.CreateProtector(TokenPurpose).ToTimeLimitedDataProtector();
        var payload = protector.Unprotect(token, out _);
        // Same payload, same key ring, expiry already in the past: the smallest honest stand-in for advancing time.
        var expired = protector.Protect(payload, DateTimeOffset.UtcNow.AddMinutes(-1));

        (await kit.Manager.GetTwoFactorProvidersAsync(expired)).Should().BeEmpty();
        (await kit.Manager.SendTwoFactorCodeAsync(expired, "Email")).ErrorMessage.Should().Be(InvalidSession);
        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(expired, "Email", kit.CodeFor(user), Tenant);

        verify.Succeeded.Should().BeFalse();
        verify.ErrorMessage.Should().Be(InvalidSession);
        await AssertNoTokensIssued(kit);
    }

    [Fact]
    public async Task TwoFactorMethods_ShouldAcceptTheSamePayload_WhenItHasNotExpired()
    {
        // Control for the expired-token test: the re-protected payload is only rejected because of its expiry.
        var (kit, user, token) = await LoggedInAsync();
        var protector = kit.DataProtection!.CreateProtector(TokenPurpose).ToTimeLimitedDataProtector();
        var payload = protector.Unprotect(token, out _);
        var fresh = protector.Protect(payload, DateTimeOffset.UtcNow.AddMinutes(1));

        var verify = await kit.Manager.VerifyTwoFactorCodeAsync(fresh, "Email", kit.CodeFor(user), Tenant);

        verify.Succeeded.Should().BeTrue();
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
        var protector = kit.DataProtection!.CreateProtector(TokenPurpose).ToTimeLimitedDataProtector();

        // Forge, with the real key ring, a payload that keeps X's stamp but names Y.
        var parts = JsonSerializer.Deserialize<string[]>(protector.Unprotect(tokenX, out _))!;
        parts[0] = y.Id.ToString();
        var swapped = protector.Protect(JsonSerializer.Serialize(parts), TimeSpan.FromMinutes(5));

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
}
