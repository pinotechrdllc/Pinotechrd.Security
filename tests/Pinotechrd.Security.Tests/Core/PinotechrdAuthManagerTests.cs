using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>Refresh, sign-out and password reset behavior of the authentication manager.</summary>
public class PinotechrdAuthManagerTests
{
    private const string Tenant = AuthManagerTestKit<RefreshUser>.DefaultTenant;
    private static readonly AuthResult InvalidToken = AuthResult.Failure("Invalid token");

    public sealed class RefreshUser : BaseSecurityUser;

    private static (AuthManagerTestKit<RefreshUser> Kit, RefreshUser User) NewKit(string? tenant = Tenant, bool withContext = true)
    {
        var kit = new AuthManagerTestKit<RefreshUser>(tenant: tenant, withTenantContext: withContext);
        var user = kit.AddUser("alice@x.test");
        return (kit, user);
    }

    private static void Consumes(AuthManagerTestKit<RefreshUser> kit, string token, RefreshTokenConsumeResult result) =>
        kit.RefreshStore.ConsumeAsync(token, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(result));

    private static RefreshTokenConsumeResult Consumed(RefreshUser user, string? stamp, string family = "family-1") =>
        new(RefreshTokenConsumeStatus.Consumed, user.Id.ToString(), Tenant, family, stamp);

    // ---- Refresh: success --------------------------------------------------------------------

    [Fact]
    public async Task RefreshAsync_ShouldRotateWithTheSameFamilyAndTheCurrentStamp_WhenTokenIsConsumed()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user), "family-9"));
        kit.TokenProvider.GenerateRefreshToken().Returns("refresh-2");
        kit.TokenProvider.GenerateAccessToken(Arg.Any<IEnumerable<System.Security.Claims.Claim>>()).Returns("access-2");

        var result = await kit.Manager.RefreshAsync("refresh-1");

        result.Succeeded.Should().BeTrue();
        result.Token!.AccessToken.Should().Be("access-2");
        result.Token.RefreshToken.Should().Be("refresh-2");
        await kit.RefreshStore.Received(1).ConsumeAsync("refresh-1", Tenant, Arg.Any<CancellationToken>());
        await kit.RefreshStore.Received(1).RotateAsync(
            "family-9", user.Id.ToString(), Tenant, "refresh-2", Arg.Any<DateTime>(),
            kit.StampOf(user), Arg.Any<CancellationToken>());
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheStoreNoLongerHasTheFamily()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user), "family-gone"));
        kit.RefreshStore.RotateAsync("family-gone", default!, default!, default!, default).ReturnsForAnyArgs(Task.FromResult(false));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);

        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldIssueTokensForExactlyTheContextTenant()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));
        IReadOnlyList<System.Security.Claims.Claim>? claims = null;
        kit.TokenProvider.GenerateAccessToken(Arg.Do<IEnumerable<System.Security.Claims.Claim>>(c => claims = c.ToList()));

        await kit.Manager.RefreshAsync("refresh-1");

        claims!.Where(c => c.Type == "tenant_id").Select(c => c.Value).Should().Equal(Tenant);
    }

    [Fact]
    public async Task RefreshAsync_ShouldNotAcceptTheOldTokenAgain_AndRevokeTheFamily_WithTheRealStore()
    {
        var store = new InMemoryRefreshTokenStore();
        var kit = new AuthManagerTestKit<RefreshUser>(tenant: Tenant, refreshStore: store);
        kit.TokenProvider.GenerateRefreshToken().Returns(_ => Guid.NewGuid().ToString("N"));
        kit.AddUser("alice@x.test");
        var login = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<RefreshUser>.Password, Tenant);
        var first = login.Token!.RefreshToken;

        var rotated = await kit.Manager.RefreshAsync(first);
        var replay = await kit.Manager.RefreshAsync(first);
        var afterReplay = await kit.Manager.RefreshAsync(rotated.Token!.RefreshToken);

        rotated.Succeeded.Should().BeTrue();
        replay.Should().Be(InvalidToken);
        afterReplay.Should().Be(InvalidToken);
    }

    // ---- Refresh: every failure is the same --------------------------------------------------

    [Theory]
    [InlineData(RefreshTokenConsumeStatus.NotFound)]
    [InlineData(RefreshTokenConsumeStatus.Expired)]
    [InlineData(RefreshTokenConsumeStatus.Revoked)]
    [InlineData(RefreshTokenConsumeStatus.Reused)]
    [InlineData(RefreshTokenConsumeStatus.TenantMismatch)]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheStoreDoesNotConsume(RefreshTokenConsumeStatus status)
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", new RefreshTokenConsumeResult(status, user.Id.ToString(), Tenant, "family-1", kit.StampOf(user)));

        var result = await kit.Manager.RefreshAsync("refresh-1");

        result.Should().Be(InvalidToken);
        kit.TokenProvider.DidNotReceiveWithAnyArgs().GenerateAccessToken(default!);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RotateAsync(default!, default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheStoreReturnsNothing()
    {
        var (kit, _) = NewKit();

        var result = await kit.Manager.RefreshAsync("unknown");

        result.Should().Be(InvalidToken);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheUserIsMissing()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", new RefreshTokenConsumeResult(
            RefreshTokenConsumeStatus.Consumed, Guid.NewGuid().ToString(), Tenant, "f", kit.StampOf(user)));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheUserIsLockedOut()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));
        kit.LockOut(user);

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RotateAsync(default!, default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldNotConsumeTheToken_WhenTheUserIsLockedOut()
    {
        var (kit, user) = NewKit();
        kit.RefreshStore.ValidateAsync("refresh-1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new RefreshTokenValidationResult(true, user.Id.ToString(), Tenant)));
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));
        kit.LockOut(user);

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);

        await kit.RefreshStore.DidNotReceiveWithAnyArgs().ConsumeAsync(default!, default!, default);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RotateAsync(default!, default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldKeepTheSessionThroughALockout_WithTheRealStore()
    {
        var store = new InMemoryRefreshTokenStore();
        var kit = new AuthManagerTestKit<RefreshUser>(tenant: Tenant, refreshStore: store);
        kit.TokenProvider.GenerateRefreshToken().Returns(_ => Guid.NewGuid().ToString("N"));
        var user = kit.AddUser("alice@x.test");
        var token = (await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<RefreshUser>.Password, Tenant)).Token!.RefreshToken;

        kit.LockOut(user);
        (await kit.Manager.RefreshAsync(token)).Should().Be(InvalidToken);
        (await store.ValidateAsync(token)).IsValid.Should().BeTrue("the refused refresh did not consume the token");
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheUserCannotSignIn()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));
        kit.SignInManager.CanSignInAsync(user).Returns(Task.FromResult(false));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RotateAsync(default!, default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheUserIsInactive()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));
        kit.MakeInactive(user);

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RotateAsync(default!, default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheSecurityStampDiffers()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, "stamp-from-before"));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RotateAsync(default!, default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheTokenCarriesNoStamp()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, stamp: null));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithoutConsuming_WhenThereIsNoTenantContext()
    {
        var (kit, user) = NewKit(withContext: false);
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().ConsumeAsync(default!, default!);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithoutConsuming_WhenTheContextHasNoTenant()
    {
        var (kit, user) = NewKit(tenant: null);
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().ConsumeAsync(default!, default!);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task RefreshAsync_ShouldFailWithoutConsuming_WhenTheTokenIsEmpty(string? token)
    {
        var (kit, _) = NewKit();

        (await kit.Manager.RefreshAsync(token!)).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().ConsumeAsync(default!, default!);
    }

    [Fact]
    public async Task RefreshAsync_ShouldReturnEqualResults_ForEveryFailure()
    {
        var (kit, user) = NewKit();
        var results = new List<AuthResult>();
        foreach (var status in new[]
                 {
                     RefreshTokenConsumeStatus.NotFound, RefreshTokenConsumeStatus.Expired, RefreshTokenConsumeStatus.Revoked,
                     RefreshTokenConsumeStatus.Reused, RefreshTokenConsumeStatus.TenantMismatch
                 })
        {
            Consumes(kit, "t", new RefreshTokenConsumeResult(status, user.Id.ToString(), Tenant, "f", kit.StampOf(user)));
            results.Add(await kit.Manager.RefreshAsync("t"));
        }
        Consumes(kit, "t", Consumed(user, "old-stamp"));
        results.Add(await kit.Manager.RefreshAsync("t"));
        Consumes(kit, "t", Consumed(user, stamp: null));
        results.Add(await kit.Manager.RefreshAsync("t"));

        results.Should().AllSatisfy(r => r.Should().Be(InvalidToken));
    }

    // ---- Self-service: sign-out and password change of the authenticated user ---------------

    private const string NewPassword = "new-password-1";

    private static ISecurityDataProvider CurrentUser(string? userId)
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        provider.GetCurrentUserId().Returns(userId);
        return provider;
    }

    private static (AuthManagerTestKit<RefreshUser> Kit, RefreshUser A, RefreshUser B) TwoUsers(
        ISecurityDataProvider? provider = null, IRefreshTokenStore? store = null)
    {
        var kit = new AuthManagerTestKit<RefreshUser>(tenant: Tenant, refreshStore: store, dataProvider: provider);
        var a = kit.AddUser("a@x.test");
        var b = kit.AddUser("b@x.test");
        return (kit, a, b);
    }

    [Fact]
    public async Task SignOutCurrentUserAsync_ShouldRevokeOnlyTheCurrentUsersTokensAndRenewItsStamp()
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        var (kit, a, b) = TwoUsers(provider, new InMemoryRefreshTokenStore());
        kit.TokenProvider.GenerateRefreshToken().Returns(_ => Guid.NewGuid().ToString("N"));
        var loginA = await kit.Manager.LoginAsync("a@x.test", AuthManagerTestKit<RefreshUser>.Password, Tenant);
        var loginB = await kit.Manager.LoginAsync("b@x.test", AuthManagerTestKit<RefreshUser>.Password, Tenant);
        var (stampA, stampB) = (kit.StampOf(a), kit.StampOf(b));
        provider.GetCurrentUserId().Returns(a.Id.ToString());

        var signedOut = await kit.Manager.SignOutCurrentUserAsync();

        signedOut.Should().BeTrue();
        (await kit.Manager.RefreshAsync(loginA.Token!.RefreshToken)).Should().Be(InvalidToken);
        (await kit.Manager.RefreshAsync(loginB.Token!.RefreshToken)).Succeeded.Should().BeTrue();
        kit.StampOf(a).Should().NotBe(stampA);
        kit.StampOf(b).Should().Be(stampB);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailAfterSignOutCurrentUser_WithTheRealStore()
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        var kit = new AuthManagerTestKit<RefreshUser>(tenant: Tenant, refreshStore: new InMemoryRefreshTokenStore(), dataProvider: provider);
        kit.TokenProvider.GenerateRefreshToken().Returns(_ => Guid.NewGuid().ToString("N"));
        var user = kit.AddUser("alice@x.test");
        provider.GetCurrentUserId().Returns(user.Id.ToString());
        var login = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<RefreshUser>.Password, Tenant);

        await kit.Manager.SignOutCurrentUserAsync();
        var result = await kit.Manager.RefreshAsync(login.Token!.RefreshToken);

        result.Should().Be(InvalidToken);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task SignOutCurrentUserAsync_ShouldReturnFalseAndChangeNothing_WhenThereIsNoAuthenticatedUser(string? currentId)
    {
        var (kit, a, _) = TwoUsers(CurrentUser(currentId));
        var stamp = kit.StampOf(a);

        (await kit.Manager.SignOutCurrentUserAsync()).Should().BeFalse();

        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
        kit.StampOf(a).Should().Be(stamp);
    }

    [Fact]
    public async Task SignOutCurrentUserAsync_ShouldReturnFalseAndChangeNothing_WhenNoDataProviderWasGiven()
    {
        var (kit, a, _) = TwoUsers();
        var stamp = kit.StampOf(a);

        (await kit.Manager.SignOutCurrentUserAsync()).Should().BeFalse();

        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
        kit.StampOf(a).Should().Be(stamp);
    }

    [Fact]
    public async Task SignOutCurrentUserAsync_ShouldReturnFalseAndChangeNothing_WhenTheCurrentUserDoesNotExist()
    {
        var (kit, _, _) = TwoUsers(CurrentUser(Guid.NewGuid().ToString()));

        (await kit.Manager.SignOutCurrentUserAsync()).Should().BeFalse();

        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
    }

    [Fact]
    public async Task ChangeOwnPasswordAsync_ShouldChangeOnlyTheCurrentUsersPassword()
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        var (kit, a, b) = TwoUsers(provider);
        provider.GetCurrentUserId().Returns(a.Id.ToString());

        var result = await kit.Manager.ChangeOwnPasswordAsync(AuthManagerTestKit<RefreshUser>.Password, NewPassword);

        result.Succeeded.Should().BeTrue();
        kit.PasswordOf(a).Should().Be(NewPassword);
        kit.PasswordOf(b).Should().Be(AuthManagerTestKit<RefreshUser>.Password);
    }

    [Fact]
    public async Task ChangeOwnPasswordAsync_ShouldFailAndKeepEveryPassword_WhenTheCurrentPasswordIsWrong()
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        var (kit, a, b) = TwoUsers(provider);
        provider.GetCurrentUserId().Returns(a.Id.ToString());

        var result = await kit.Manager.ChangeOwnPasswordAsync("not-the-password", NewPassword);

        result.Succeeded.Should().BeFalse();
        kit.PasswordOf(a).Should().Be(AuthManagerTestKit<RefreshUser>.Password);
        kit.PasswordOf(b).Should().Be(AuthManagerTestKit<RefreshUser>.Password);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ChangeOwnPasswordAsync_ShouldFailWithUserNotFoundAndChangeNothing_WhenThereIsNoAuthenticatedUser(string? currentId)
    {
        var (kit, a, b) = TwoUsers(CurrentUser(currentId));

        var result = await kit.Manager.ChangeOwnPasswordAsync(AuthManagerTestKit<RefreshUser>.Password, NewPassword);

        result.Should().Be(AuthResult.Failure("User not found"));
        await kit.UserManager.DidNotReceiveWithAnyArgs().ChangePasswordAsync(default!, default!, default!);
        kit.PasswordOf(a).Should().Be(AuthManagerTestKit<RefreshUser>.Password);
        kit.PasswordOf(b).Should().Be(AuthManagerTestKit<RefreshUser>.Password);
    }

    [Fact]
    public async Task ChangeOwnPasswordAsync_ShouldFailWithUserNotFoundAndChangeNothing_WhenNoDataProviderWasGiven()
    {
        var (kit, a, _) = TwoUsers();

        var result = await kit.Manager.ChangeOwnPasswordAsync(AuthManagerTestKit<RefreshUser>.Password, NewPassword);

        result.Should().Be(AuthResult.Failure("User not found"));
        await kit.UserManager.DidNotReceiveWithAnyArgs().ChangePasswordAsync(default!, default!, default!);
        kit.PasswordOf(a).Should().Be(AuthManagerTestKit<RefreshUser>.Password);
    }

    [Fact]
    public async Task ChangeOwnPasswordAsync_ShouldFailWithUserNotFound_WhenTheCurrentUserDoesNotExist()
    {
        var (kit, _, _) = TwoUsers(CurrentUser(Guid.NewGuid().ToString()));

        var result = await kit.Manager.ChangeOwnPasswordAsync(AuthManagerTestKit<RefreshUser>.Password, NewPassword);

        result.Should().Be(AuthResult.Failure("User not found"));
        await kit.UserManager.DidNotReceiveWithAnyArgs().ChangePasswordAsync(default!, default!, default!);
    }

    [Fact]
    public async Task SignOutCurrentUserAsync_ShouldReturnFalseButKeepTheTokensRevoked_WhenTheStampCannotBeRenewed()
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        var (kit, a, _) = TwoUsers(provider);
        provider.GetCurrentUserId().Returns(a.Id.ToString());
        kit.MakeStampUpdateFail(a);

        var signedOut = await kit.Manager.SignOutCurrentUserAsync();

        signedOut.Should().BeFalse();
        await kit.RefreshStore.Received(1).RevokeAllForUserAsync(a.Id.ToString(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SignOutCurrentUserAsync_ShouldReturnTrueAndRevokeTokensWithoutTouchingTheStamp_WhenTheStoreHasNoSecurityStamps()
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        var (kit, a, _) = TwoUsers(provider);
        provider.GetCurrentUserId().Returns(a.Id.ToString());
        kit.UserManager.SupportsUserSecurityStamp.Returns(false);

        var signedOut = await kit.Manager.SignOutCurrentUserAsync();

        signedOut.Should().BeTrue();
        await kit.RefreshStore.Received(1).RevokeAllForUserAsync(a.Id.ToString(), Arg.Any<CancellationToken>());
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
    }

    [Fact]
    public async Task SignOutCurrentUserAsync_ShouldRevokeUnderTheStoredId_WhenTheLookupMatchedAnotherSpellingOfTheId()
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        var (kit, a, _) = TwoUsers(provider);
        var upper = a.Id.ToString().ToUpperInvariant();
        upper.Should().NotBe(a.Id.ToString());
        provider.GetCurrentUserId().Returns(upper);
        kit.UserManager.FindByIdAsync(upper).Returns(Task.FromResult<RefreshUser?>(a));

        var signedOut = await kit.Manager.SignOutCurrentUserAsync();

        signedOut.Should().BeTrue();
        await kit.RefreshStore.Received(1).RevokeAllForUserAsync(a.Id.ToString(), Arg.Any<CancellationToken>());
        await kit.RefreshStore.DidNotReceive().RevokeAllForUserAsync(upper, Arg.Any<CancellationToken>());
    }

    // ---- Password reset ----------------------------------------------------------------------

    [Fact]
    public async Task ResetPasswordAsync_ShouldReturnTheSameResultForAnUnknownEmailAndAnInvalidToken()
    {
        var (kit, user) = NewKit();
        kit.UserManager.ResetPasswordAsync(user, "bad-token", "NewPassw0rd!")
            .Returns(Task.FromResult(IdentityResult.Failed(new IdentityErrorDescriber().InvalidToken())));

        var unknown = await kit.Manager.ResetPasswordAsync("nobody@x.test", "bad-token", "NewPassw0rd!");
        var badToken = await kit.Manager.ResetPasswordAsync("alice@x.test", "bad-token", "NewPassw0rd!");

        unknown.Succeeded.Should().BeFalse();
        unknown.Should().Be(badToken);
    }

    // ---- Host validator ---------------------------------------------------------------------

    [Fact]
    public async Task RefreshAsync_ShouldReturnExactlyInvalidToken_WhenTheIdentityValidatorFails()
    {
        var validator = Substitute.For<IIdentityValidator<RefreshUser>>();
        validator.ValidateAsync(Arg.Any<RefreshUser>(), Arg.Any<string>())
            .Returns(Task.FromResult(IdentityValidationResult.Failure("Employee 4711 is suspended in tenant tenant-a")));
        var kit = new AuthManagerTestKit<RefreshUser>(tenant: Tenant, identityValidator: validator);
        var user = kit.AddUser("alice@x.test");
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));

        var result = await kit.Manager.RefreshAsync("refresh-1");

        result.Should().Be(InvalidToken);
        await validator.Received(1).ValidateAsync(user, Tenant);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().RotateAsync(default!, default!, default!, default!, default);
    }

    [Fact]
    public async Task LoginAsync_ShouldReportTheValidatorMessage_ButRefreshHidesIt()
    {
        var validator = Substitute.For<IIdentityValidator<RefreshUser>>();
        validator.ValidateAsync(Arg.Any<RefreshUser>(), Arg.Any<string>())
            .Returns(Task.FromResult(IdentityValidationResult.Failure("not a member")));
        var kit = new AuthManagerTestKit<RefreshUser>(tenant: Tenant, identityValidator: validator);
        var user = kit.AddUser("alice@x.test");
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));

        var login = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<RefreshUser>.Password, Tenant);
        var refresh = await kit.Manager.RefreshAsync("refresh-1");

        login.Succeeded.Should().BeFalse();
        login.ErrorMessage.Should().Be("not a member");
        refresh.ErrorMessage.Should().Be("Invalid token");
    }
}
