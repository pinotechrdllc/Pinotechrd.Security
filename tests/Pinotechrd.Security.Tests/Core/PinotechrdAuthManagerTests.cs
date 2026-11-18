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
        await kit.RefreshStore.Received(1).SaveAsync(
            user.Id.ToString(), Tenant, "refresh-2", Arg.Any<DateTime>(),
            "family-9", kit.StampOf(user), Arg.Any<CancellationToken>());
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
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheUserCannotSignIn()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));
        kit.SignInManager.CanSignInAsync(user).Returns(Task.FromResult(false));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheUserIsInactive()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, kit.StampOf(user)));
        kit.MakeInactive(user);

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailWithInvalidToken_WhenTheSecurityStampDiffers()
    {
        var (kit, user) = NewKit();
        Consumes(kit, "refresh-1", Consumed(user, "stamp-from-before"));

        (await kit.Manager.RefreshAsync("refresh-1")).Should().Be(InvalidToken);
        await kit.RefreshStore.DidNotReceiveWithAnyArgs().SaveAsync(default!, default!, default!, default);
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

    // ---- Sign-out ----------------------------------------------------------------------------

    [Fact]
    public async Task SignOutAsync_ShouldRevokeAllRefreshTokensAndRenewTheStamp_WhenTheUserExists()
    {
        var (kit, user) = NewKit();
        var stamp = kit.StampOf(user);

        await kit.Manager.SignOutAsync(user.Id.ToString());

        await kit.RefreshStore.Received(1).RevokeAllForUserAsync(user.Id.ToString(), Arg.Any<CancellationToken>());
        await kit.UserManager.Received(1).UpdateSecurityStampAsync(user);
        kit.StampOf(user).Should().NotBe(stamp);
    }

    [Fact]
    public async Task SignOutAsync_ShouldStillRevokeTokensAndNotThrow_WhenTheUserIsUnknown()
    {
        var (kit, _) = NewKit();
        var unknown = Guid.NewGuid().ToString();

        var act = () => kit.Manager.SignOutAsync(unknown);

        await act.Should().NotThrowAsync();
        await kit.RefreshStore.Received(1).RevokeAllForUserAsync(unknown, Arg.Any<CancellationToken>());
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
    }

    [Fact]
    public async Task RefreshAsync_ShouldFailAfterSignOut_WithTheRealStore()
    {
        var store = new InMemoryRefreshTokenStore();
        var kit = new AuthManagerTestKit<RefreshUser>(tenant: Tenant, refreshStore: store);
        kit.TokenProvider.GenerateRefreshToken().Returns(_ => Guid.NewGuid().ToString("N"));
        var user = kit.AddUser("alice@x.test");
        var login = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<RefreshUser>.Password, Tenant);

        await kit.Manager.SignOutAsync(user.Id.ToString());
        var result = await kit.Manager.RefreshAsync(login.Token!.RefreshToken);

        result.Should().Be(InvalidToken);
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
}
